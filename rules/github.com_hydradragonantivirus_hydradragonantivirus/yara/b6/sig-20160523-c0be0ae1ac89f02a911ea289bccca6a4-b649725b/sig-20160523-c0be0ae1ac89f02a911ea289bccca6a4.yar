rule sig_20160523_c0be0ae1ac89f02a911ea289bccca6a4 {
  meta:
    description = "datamaliciousorder - file 20160523_c0be0ae1ac89f02a911ea289bccca6a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b63e761d0d56077fa756c52ef8a96494640b3a4bb324f459d52e6a1974688707"

  strings:
    $s1 = "verse().join('');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}