rule TTP_XOR_WriteProcessMemory_3870 {
  strings:
    $key_3870 = { 6f 02 [2] 5d 20 [2] 5b 15 [2] 75 15 [2] 4a 09 }

  condition:
    any of them
}