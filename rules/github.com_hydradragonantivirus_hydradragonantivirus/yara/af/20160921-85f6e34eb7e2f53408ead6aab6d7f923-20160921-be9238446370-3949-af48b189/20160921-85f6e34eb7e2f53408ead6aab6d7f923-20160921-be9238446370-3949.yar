rule _20160921_85f6e34eb7e2f53408ead6aab6d7f923_20160921_be9238446370_3949 {
  meta:
    description = "datamaliciousorder - from files 20160921_85f6e34eb7e2f53408ead6aab6d7f923.js, 20160921_be923844637026740bc9e5a4aad21ebe.js, 20160921_e0f34764de4fcb908eef371ab4011f31.js, 20160921_fff847efa0eaa326a0aad4d2fc81d41e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5005d4ac4c04b94b5c8e15a81b5b50ecf9189f0e4afa203ae5195bec5a82b02f"
    hash2       = "f50e7368497d3ab714aae3798280c1b53ff9f91f0081f1eafa0b9e23e4928336"
    hash3       = "de457f8d789ffcd672900ad06037697526230f620a01d113732fa3683b1604b1"
    hash4       = "93f868a10878cb41f305e28c8802778903c99b84a1bc0647a0c2c78fd6310577"

  strings:
    $s1 = "return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})()," ascii
    $s2 = "nction f000(){return \"QDg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){retu" ascii
    $s3 = " \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Yi\";})(),(func" ascii
    $s4 = "(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UEg\";})(),(function f000" ascii
    $s5 = "n f000(){return \"Qz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"" ascii
    $s6 = "(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}