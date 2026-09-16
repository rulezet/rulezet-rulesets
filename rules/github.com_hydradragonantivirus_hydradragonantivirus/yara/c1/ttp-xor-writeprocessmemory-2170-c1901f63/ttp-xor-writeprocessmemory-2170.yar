rule TTP_XOR_WriteProcessMemory_2170 {
  strings:
    $key_2170 = { 76 02 [2] 44 20 [2] 42 15 [2] 6c 15 [2] 53 09 }

  condition:
    any of them
}