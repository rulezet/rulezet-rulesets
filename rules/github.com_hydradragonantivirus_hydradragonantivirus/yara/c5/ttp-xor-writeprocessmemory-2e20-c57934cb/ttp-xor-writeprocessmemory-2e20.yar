rule TTP_XOR_WriteProcessMemory_2e20 {
  strings:
    $key_2e20 = { 79 52 [2] 4b 70 [2] 4d 45 [2] 63 45 [2] 5c 59 }

  condition:
    any of them
}