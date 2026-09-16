rule TTP_XOR_QUAD_CurrentVersionRun_adb1 {
  strings:
    $key_adb1 = { fe de [2] da d0 [2] f1 fc [2] df de [2] cb c5 [2] c4 df [2] da c2 [2] d8 c3 [2] c3 c5 [2] df c2 [2] c3 ed }

  condition:
    any of them
}