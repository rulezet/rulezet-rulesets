rule TTP_XOR_QUAD_CurrentVersionRun_adb0 {
  strings:
    $key_adb0 = { fe df [2] da d1 [2] f1 fd [2] df df [2] cb c4 [2] c4 de [2] da c3 [2] d8 c2 [2] c3 c4 [2] df c3 [2] c3 ec }

  condition:
    any of them
}