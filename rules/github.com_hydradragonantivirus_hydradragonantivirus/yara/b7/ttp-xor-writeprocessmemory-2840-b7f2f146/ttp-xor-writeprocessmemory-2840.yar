rule TTP_XOR_WriteProcessMemory_2840 {
  strings:
    $key_2840 = { 7f 32 [2] 4d 10 [2] 4b 25 [2] 65 25 [2] 5a 39 }

  condition:
    any of them
}