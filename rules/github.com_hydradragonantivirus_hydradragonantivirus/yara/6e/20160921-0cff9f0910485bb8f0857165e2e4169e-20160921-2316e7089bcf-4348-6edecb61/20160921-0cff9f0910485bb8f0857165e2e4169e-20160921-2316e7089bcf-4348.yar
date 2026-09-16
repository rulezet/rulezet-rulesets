rule _20160921_0cff9f0910485bb8f0857165e2e4169e_20160921_2316e7089bcf_4348 {
  meta:
    description = "datamaliciousorder - from files 20160921_0cff9f0910485bb8f0857165e2e4169e.js, 20160921_2316e7089bcfa9e840be327e9e562c57.js, 20160921_dc8499faf06c485edd1ddc8df3a39f1c.js, 20160921_f232e0ba2dbd66b232f717e912f70cd7.js, 20160921_f75fc7d6e5f9a9e633ed6b173201a2a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dbe3dcf31ef6a75ca25b690245a2ec8ebd1f75d9a20a2b5dac46791b6ad354f"
    hash2       = "11216ce48a9d383f0d3cab03de05ba1550ae25c7b5d18a758666cfdd75159fe2"
    hash3       = "f991a0c08a08712da63725a1264034411c38050f80181edfb6cee6760198ffd6"
    hash4       = "d8231c7ebf650f58f63f7ed6d3017e0ee9895c1dd821750dcc6c78003fc81b2b"
    hash5       = "b78b074fdbad3a2d311b3fe1363fedad42cd9a804cba11641844abee41e9ad5f"

  strings:
    $s1 = "unction f000(){return \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){re" ascii
    $s2 = "000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa" ascii
    $s3 = "n f000(){return \"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"" ascii
    $s4 = "){return \"DNa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";" ascii
    $s5 = " f000(){return \"Kw\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"W" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}