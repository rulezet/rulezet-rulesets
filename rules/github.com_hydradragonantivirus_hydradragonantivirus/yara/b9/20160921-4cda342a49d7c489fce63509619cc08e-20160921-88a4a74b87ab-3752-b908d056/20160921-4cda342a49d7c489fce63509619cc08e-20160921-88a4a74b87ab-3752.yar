rule _20160921_4cda342a49d7c489fce63509619cc08e_20160921_88a4a74b87ab_3752 {
  meta:
    description = "datamaliciousorder - from files 20160921_4cda342a49d7c489fce63509619cc08e.js, 20160921_88a4a74b87ab9fd3fb3dd307f9d7213d.js, 20160921_b23a0d871d76c64a3c71f0b0f52faaa8.js, 20160921_b5efb4ba3e712545d64a2d00b3dcd76e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cabf2bed3c4b1c46c86905c48d0ce38dc15e155546fd36ce4d681314485c6aeb"
    hash2       = "33ff531b193580829a3217137df52750b8df810994123bd1d02bfced3fa6c2ce"
    hash3       = "02969139df11550b994530c0bcbc6d946b6e49105015e9475f5de3942d78e5a1"
    hash4       = "ff8ef85b589636068d365f9ee4a0b9c7119baeb269d0a34c9810fca4b3faf1cf"

  strings:
    $s1 = " \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(func" ascii
    $s2 = "i\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function" ascii
    $s3 = "ion fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return" ascii
    $s4 = "urn \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Jo\";})(),(f" ascii
    $s5 = "{return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})" ascii
    $s6 = ",(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}