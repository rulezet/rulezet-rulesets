rule TTP_XOR_WriteProcessMemory_7870 {
  strings:
    $key_7870 = { 2f 02 [2] 1d 20 [2] 1b 15 [2] 35 15 [2] 0a 09 }

  condition:
    any of them
}