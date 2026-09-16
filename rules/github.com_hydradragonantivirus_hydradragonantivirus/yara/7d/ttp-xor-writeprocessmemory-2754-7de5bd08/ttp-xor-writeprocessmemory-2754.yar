rule TTP_XOR_WriteProcessMemory_2754 {
  strings:
    $key_2754 = { 70 26 [2] 42 04 [2] 44 31 [2] 6a 31 [2] 55 2d }

  condition:
    any of them
}