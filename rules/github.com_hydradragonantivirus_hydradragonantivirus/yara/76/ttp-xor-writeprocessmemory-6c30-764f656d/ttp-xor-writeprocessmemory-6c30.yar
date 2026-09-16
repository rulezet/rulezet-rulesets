rule TTP_XOR_WriteProcessMemory_6c30 {
  strings:
    $key_6c30 = { 3b 42 [2] 09 60 [2] 0f 55 [2] 21 55 [2] 1e 49 }

  condition:
    any of them
}