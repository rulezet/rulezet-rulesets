rule TTP_XOR_WriteProcessMemory_0f10 {
  strings:
    $key_0f10 = { 58 62 [2] 6a 40 [2] 6c 75 [2] 42 75 [2] 7d 69 }

  condition:
    any of them
}