rule TTP_XOR_WriteProcessMemory_6c60 {
  strings:
    $key_6c60 = { 3b 12 [2] 09 30 [2] 0f 05 [2] 21 05 [2] 1e 19 }

  condition:
    any of them
}