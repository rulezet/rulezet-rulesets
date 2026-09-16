rule TTP_XOR_WriteProcessMemory_4275 {
  strings:
    $key_4275 = { 15 07 [2] 27 25 [2] 21 10 [2] 0f 10 [2] 30 0c }

  condition:
    any of them
}