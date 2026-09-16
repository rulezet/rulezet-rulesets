rule _20160921_1ccc6f9d608f6057f34a9f01f0cf5abe_20160921_61ffae07802b_4614 {
  meta:
    description = "datamaliciousorder - from files 20160921_1ccc6f9d608f6057f34a9f01f0cf5abe.js, 20160921_61ffae07802bf5013fbbf8f137c827c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "226d26c073abdcaab4155bb0b8d789289cf0a453f58c9f6383385cc78660a27e"
    hash2       = "d1b5dbd3605683fd0b3b1dc802f1048401a8db23070c8205273f5c5ab6c5133c"

  strings:
    $s1 = "nction f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s2 = "),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Oh\";})(),(function f000()" ascii
    $s3 = "n \"BMj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(fu" ascii
    $s4 = "eturn \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})()" ascii
    $s5 = "on f000(){return \"Zj\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}