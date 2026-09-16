rule Ventrilo_encryption_decryption_algorithm__32_lil_44_ {
  strings:
    $a0 = { aa 00 00 00 55 00 00 00 22 00 00 00 cc 00 00 00 69 00 00 00 7c 00 00 00 38 00 00 00 91 00 00 00 88 00 00 00 f5 00 00 00 e1 00 00 00 }

  condition:
    $a0
}