rule TTP_XOR_WriteProcessMemory_2723 {
  strings:
    $key_2723 = { 70 51 [2] 42 73 [2] 44 46 [2] 6a 46 [2] 55 5a }

  condition:
    any of them
}