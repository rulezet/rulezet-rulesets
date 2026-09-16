rule TTP_XOR_WriteProcessMemory_6c10 {
  strings:
    $key_6c10 = { 3b 62 [2] 09 40 [2] 0f 75 [2] 21 75 [2] 1e 69 }

  condition:
    any of them
}