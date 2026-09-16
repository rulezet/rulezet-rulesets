rule TTP_XOR_WriteProcessMemory_3823 {
  strings:
    $key_3823 = { 6f 51 [2] 5d 73 [2] 5b 46 [2] 75 46 [2] 4a 5a }

  condition:
    any of them
}