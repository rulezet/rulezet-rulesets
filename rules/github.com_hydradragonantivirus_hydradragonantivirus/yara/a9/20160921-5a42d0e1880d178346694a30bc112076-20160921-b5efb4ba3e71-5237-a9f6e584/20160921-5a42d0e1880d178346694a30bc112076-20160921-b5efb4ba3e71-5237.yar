rule _20160921_5a42d0e1880d178346694a30bc112076_20160921_b5efb4ba3e71_5237 {
  meta:
    description = "datamaliciousorder - from files 20160921_5a42d0e1880d178346694a30bc112076.js, 20160921_b5efb4ba3e712545d64a2d00b3dcd76e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca8e81eec437e87b27dedb202751f13e736aa092e78fffde5fbf40616f2e3738"
    hash2       = "ff8ef85b589636068d365f9ee4a0b9c7119baeb269d0a34c9810fca4b3faf1cf"

  strings:
    $s1 = "eturn \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Py\";})()," ascii
    $s2 = "uck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py" ascii
    $s3 = "(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Py\";})(),(function fuck(){re" ascii
    $s4 = "{return \"AUx\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"ZWu\";})" ascii
    $s5 = "uck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"GNm" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}