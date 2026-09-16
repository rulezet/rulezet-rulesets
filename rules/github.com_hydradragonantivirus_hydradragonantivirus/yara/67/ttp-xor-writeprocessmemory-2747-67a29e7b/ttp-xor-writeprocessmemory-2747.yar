rule TTP_XOR_WriteProcessMemory_2747 {
  strings:
    $key_2747 = { 70 35 [2] 42 17 [2] 44 22 [2] 6a 22 [2] 55 3e }

  condition:
    any of them
}