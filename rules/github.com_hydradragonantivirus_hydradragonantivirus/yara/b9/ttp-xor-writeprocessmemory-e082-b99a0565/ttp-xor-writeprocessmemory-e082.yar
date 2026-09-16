rule TTP_XOR_WriteProcessMemory_e082 {
  strings:
    $key_e082 = { b7 f0 [2] 85 d2 [2] 83 e7 [2] ad e7 [2] 92 fb }

  condition:
    any of them
}