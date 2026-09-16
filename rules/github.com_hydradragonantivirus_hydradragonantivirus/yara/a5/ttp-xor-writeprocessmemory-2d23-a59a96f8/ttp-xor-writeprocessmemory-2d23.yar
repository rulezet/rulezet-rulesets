rule TTP_XOR_WriteProcessMemory_2d23 {
  strings:
    $key_2d23 = { 7a 51 [2] 48 73 [2] 4e 46 [2] 60 46 [2] 5f 5a }

  condition:
    any of them
}