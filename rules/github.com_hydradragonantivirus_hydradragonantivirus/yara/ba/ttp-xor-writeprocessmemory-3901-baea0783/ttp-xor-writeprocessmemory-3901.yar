rule TTP_XOR_WriteProcessMemory_3901 {
  strings:
    $key_3901 = { 6e 73 [2] 5c 51 [2] 5a 64 [2] 74 64 [2] 4b 78 }

  condition:
    any of them
}