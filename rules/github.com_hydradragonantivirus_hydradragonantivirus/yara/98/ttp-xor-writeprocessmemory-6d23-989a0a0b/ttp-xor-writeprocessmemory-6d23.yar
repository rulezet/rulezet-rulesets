rule TTP_XOR_WriteProcessMemory_6d23 {
  strings:
    $key_6d23 = { 3a 51 [2] 08 73 [2] 0e 46 [2] 20 46 [2] 1f 5a }

  condition:
    any of them
}