rule TTP_XOR_WriteProcessMemory_7482 {
  strings:
    $key_7482 = { 23 f0 [2] 11 d2 [2] 17 e7 [2] 39 e7 [2] 06 fb }

  condition:
    any of them
}