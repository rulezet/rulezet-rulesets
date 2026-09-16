rule _20160921_4787695fef4453a16be881bbe0f96c1a_20160921_9d32b55f93b8_5077 {
  meta:
    description = "datamaliciousorder - from files 20160921_4787695fef4453a16be881bbe0f96c1a.js, 20160921_9d32b55f93b83e117524c4df15361eee.js, 20160921_dd28b3b2e4fae279f1dc4ba30acafda9.js, 20160921_e6569e3fc498e9fab243cf8dcef2ac51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a11e3d64ee2711e84433d2b8035ce0dafbcffa760c2026e3cfe9ba310008f90"
    hash2       = "3fe6572823305aa2316dd2ce562c85b9f6eb40f26ee354b5e0ff97b66cffd652"
    hash3       = "841abb0789337235f3a5367c6d4aa3806741a639f1faf0d54e41f125ecc1be02"
    hash4       = "d08c501a52afbdcde7669d2b9c40865025e38aa75b2aebf8c71433565dbc7010"

  strings:
    $s1 = "000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc" ascii
    $s2 = " \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s3 = "Db\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(functio" ascii
    $s4 = "ction f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){retur" ascii
    $s5 = "(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Yi\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}