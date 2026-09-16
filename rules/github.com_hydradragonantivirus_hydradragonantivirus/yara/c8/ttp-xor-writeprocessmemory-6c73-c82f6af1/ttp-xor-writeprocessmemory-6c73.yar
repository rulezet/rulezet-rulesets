rule TTP_XOR_WriteProcessMemory_6c73 {
  strings:
    $key_6c73 = { 3b 01 [2] 09 23 [2] 0f 16 [2] 21 16 [2] 1e 0a }

  condition:
    any of them
}