rule TTP_XOR_WriteProcessMemory_4f87 {
  strings:
    $key_4f87 = { 18 f5 [2] 2a d7 [2] 2c e2 [2] 02 e2 [2] 3d fe }

  condition:
    any of them
}