rule TTP_XOR_WriteProcessMemory_6082 {
  strings:
    $key_6082 = { 37 f0 [2] 05 d2 [2] 03 e7 [2] 2d e7 [2] 12 fb }

  condition:
    any of them
}