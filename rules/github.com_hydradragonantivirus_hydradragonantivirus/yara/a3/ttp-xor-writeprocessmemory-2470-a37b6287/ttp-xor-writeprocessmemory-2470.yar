rule TTP_XOR_WriteProcessMemory_2470 {
  strings:
    $key_2470 = { 73 02 [2] 41 20 [2] 47 15 [2] 69 15 [2] 56 09 }

  condition:
    any of them
}