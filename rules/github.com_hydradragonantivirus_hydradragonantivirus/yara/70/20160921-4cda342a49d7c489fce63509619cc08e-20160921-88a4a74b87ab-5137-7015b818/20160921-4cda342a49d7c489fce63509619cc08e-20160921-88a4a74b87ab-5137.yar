rule _20160921_4cda342a49d7c489fce63509619cc08e_20160921_88a4a74b87ab_5137 {
  meta:
    description = "datamaliciousorder - from files 20160921_4cda342a49d7c489fce63509619cc08e.js, 20160921_88a4a74b87ab9fd3fb3dd307f9d7213d.js, 20160921_9eb4e3262a9bc5c5f03ba0b7b62a3347.js, 20160921_b5efb4ba3e712545d64a2d00b3dcd76e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cabf2bed3c4b1c46c86905c48d0ce38dc15e155546fd36ce4d681314485c6aeb"
    hash2       = "33ff531b193580829a3217137df52750b8df810994123bd1d02bfced3fa6c2ce"
    hash3       = "03bf8e47f97cab996cc7f2d8147659dc1143ccbe1fd09af6b8689379f7263407"
    hash4       = "ff8ef85b589636068d365f9ee4a0b9c7119baeb269d0a34c9810fca4b3faf1cf"

  strings:
    $s1 = "Dy\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii
    $s2 = "(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"RAi\";" ascii
    $s3 = "rn \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(fu" ascii
    $s4 = "rn \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(fun" ascii
    $s5 = "uck(){return \"MBg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}