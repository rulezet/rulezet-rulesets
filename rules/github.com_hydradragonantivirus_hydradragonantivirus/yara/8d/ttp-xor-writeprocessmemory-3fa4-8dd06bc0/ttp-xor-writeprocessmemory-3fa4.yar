rule TTP_XOR_WriteProcessMemory_3fa4 {
  strings:
    $key_3fa4 = { 68 d6 [2] 5a f4 [2] 5c c1 [2] 72 c1 [2] 4d dd }

  condition:
    any of them
}