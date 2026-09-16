rule TTP_XOR_WriteProcessMemory_2734 {
  strings:
    $key_2734 = { 70 46 [2] 42 64 [2] 44 51 [2] 6a 51 [2] 55 4d }

  condition:
    any of them
}