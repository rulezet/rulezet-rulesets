rule ARKBIRD_SOLG_Ran_ELF_EXX_Nov_2020_1: FILE {
  meta:
    description = "Detect EXX variant ELF ransomware"
    author      = "Arkbird_SOLG"
    id          = "fe85d480-317a-51c3-a817-fc9034e2944f"
    date        = "2020-12-09"
    modified    = "2020-12-09"
    reference   = "Internal Research"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-12-09/EXX/Ran_ELF_EXX_Nov_2020_1.yar#L1-L28"
    license_url = "N/A"
    logic_hash  = "4508a0cf79d0d85959009f59e1471cbf123fa24f5c21da5801e91ed0bbe8a085"
    score       = 50
    quality     = 73
    tags        = "FILE"
    level       = "experimental"
    hash1       = "cb408d45762a628872fa782109e8fcfc3a5bf456074b007de21e9331bb3c5849"

  strings:
    $dbg1 = "Unexpected error, return code = %08X\n"
    $dbg2 = { 47 72 65 65 74 69 6e 67 73 20 [3-10] 21 }
    $dbg3 = "cycles=%lu ratio=%lu millisecs=%lu secs=%lu hardfail=%d a=%lu b=%lu\n"
    $dbg4 = "SHA-%d test #%d:"
    $lib1 = "pthread_mutex_unlock@@GLIBC_2.2.5" fullword ascii
    $lib2 = "pthread_mutex_lock@@GLIBC_2.2.5" fullword ascii
    $lib3 = "mbedtls_rsa_import" fullword ascii
    $lib4 = "mbedtls_rsa_export" fullword ascii
    $lib5 = "mbedtls_oid_get_extended_key_usage" fullword ascii
    $lib6 = "mbedtls_sha256_process" fullword ascii
    $seq1 = { 48 83 ec 20 89 7d ec 48 89 75 e0 b8 00 00 00 00 e8 77 00 00 00 48 8d 45 f0 b9 00 00 00 00 48 8d 15 b5 ff ff ff be 00 00 00 00 48 89 c7 e8 d6 fb ff ff c7 45 fc 01 00 00 00 eb }
    $seq2 = { 00 00 00 00 e8 b2 fe ff ff 48 8b 45 e8 48 89 c7 e8 92 ed ff ff 48 83 c0 01 48 89 c7 e8 c6 ee ff ff 48 89 45 f8 48 83 7d f8 00 74 3a 48 8b 55 e8 48 8b 45 f8 48 89 d6 48 89 c7 e8 f8 ec ff ff 48 8b 45 f8 48 89 c7 e8 12 fd ff ff 48 8b 45 f8 48 89 c7 e8 90 ec ff ff b8 00 00 00 00 e8 95 fc ff ff }
    $seq3 = { e5 41 55 41 54 53 48 81 ec 18 18 00 00 c7 45 dc 00 00 00 00 48 c7 45 d0 00 00 00 00 bf 00 00 00 00 e8 13 fd ff ff 89 c7 e8 7c fc ff ff e8 d7 fd ff ff 41 89 c5 e8 cf fd ff ff 41 89 c4 e8 c7 fd ff ff 89 c3 e8 c0 fd ff ff 89 c2 48 8d 85 d0 e7 ff ff 4d 89 e9 4d 89 e0 48 89 d9 48 8d 35 bf 0a 02 00 48 89 }

  condition:
    uint16(0) == 0x457f and filesize > 80KB and 3 of ($dbg*) and 4 of ($lib*) and 2 of ($seq*)
}