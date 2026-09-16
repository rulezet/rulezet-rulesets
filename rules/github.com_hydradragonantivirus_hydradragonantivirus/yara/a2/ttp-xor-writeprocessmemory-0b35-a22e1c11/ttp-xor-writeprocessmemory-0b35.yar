rule TTP_XOR_WriteProcessMemory_0b35 {
  strings:
    $key_0b35 = { 5c 47 [2] 6e 65 [2] 68 50 [2] 46 50 [2] 79 4c }

  condition:
    any of them
}