rule TTP_XOR_WriteProcessMemory_2950 {
  strings:
    $key_2950 = { 7e 22 [2] 4c 00 [2] 4a 35 [2] 64 35 [2] 5b 29 }

  condition:
    any of them
}