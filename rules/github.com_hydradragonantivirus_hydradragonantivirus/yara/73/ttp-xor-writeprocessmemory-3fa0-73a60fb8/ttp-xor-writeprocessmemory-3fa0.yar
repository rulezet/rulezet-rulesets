rule TTP_XOR_WriteProcessMemory_3fa0 {
  strings:
    $key_3fa0 = { 68 d2 [2] 5a f0 [2] 5c c5 [2] 72 c5 [2] 4d d9 }

  condition:
    any of them
}