rule TTP_XOR_WriteProcessMemory_0282 {
  strings:
    $key_0282 = { 55 f0 [2] 67 d2 [2] 61 e7 [2] 4f e7 [2] 70 fb }

  condition:
    any of them
}