rule TTP_XOR_WriteProcessMemory_27ed {
  strings:
    $key_27ed = { 70 9f [2] 42 bd [2] 44 88 [2] 6a 88 [2] 55 94 }

  condition:
    any of them
}