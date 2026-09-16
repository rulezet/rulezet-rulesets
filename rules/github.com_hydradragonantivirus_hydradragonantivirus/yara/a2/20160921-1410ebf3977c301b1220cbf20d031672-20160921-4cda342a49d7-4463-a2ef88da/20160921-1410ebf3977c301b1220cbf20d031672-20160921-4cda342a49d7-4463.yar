rule _20160921_1410ebf3977c301b1220cbf20d031672_20160921_4cda342a49d7_4463 {
  meta:
    description = "datamaliciousorder - from files 20160921_1410ebf3977c301b1220cbf20d031672.js, 20160921_4cda342a49d7c489fce63509619cc08e.js, 20160921_88a4a74b87ab9fd3fb3dd307f9d7213d.js, 20160921_b5efb4ba3e712545d64a2d00b3dcd76e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bba6a8e474a809cf21b57641f08c798b1175b5bb510dcebc8d2284017c4579ab"
    hash2       = "cabf2bed3c4b1c46c86905c48d0ce38dc15e155546fd36ce4d681314485c6aeb"
    hash3       = "33ff531b193580829a3217137df52750b8df810994123bd1d02bfced3fa6c2ce"
    hash4       = "ff8ef85b589636068d365f9ee4a0b9c7119baeb269d0a34c9810fca4b3faf1cf"

  strings:
    $s1 = "turn \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Np\";})(),(" ascii
    $s2 = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){ret" ascii
    $s3 = "on fuck(){return \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s4 = "uck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"AD" ascii
    $s5 = "uck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}