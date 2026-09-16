rule TTP_XOR_WriteProcessMemory_6cf0 {
  strings:
    $key_6cf0 = { 3b 82 [2] 09 a0 [2] 0f 95 [2] 21 95 [2] 1e 89 }

  condition:
    any of them
}