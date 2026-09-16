rule TTP_XOR_WriteProcessMemory_ce87 {
  strings:
    $key_ce87 = { 99 f5 [2] ab d7 [2] ad e2 [2] 83 e2 [2] bc fe }

  condition:
    any of them
}