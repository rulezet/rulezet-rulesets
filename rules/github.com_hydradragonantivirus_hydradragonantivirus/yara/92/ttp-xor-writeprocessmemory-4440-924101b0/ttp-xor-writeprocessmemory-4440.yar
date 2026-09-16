rule TTP_XOR_WriteProcessMemory_4440 {
  strings:
    $key_4440 = { 13 32 [2] 21 10 [2] 27 25 [2] 09 25 [2] 36 39 }

  condition:
    any of them
}