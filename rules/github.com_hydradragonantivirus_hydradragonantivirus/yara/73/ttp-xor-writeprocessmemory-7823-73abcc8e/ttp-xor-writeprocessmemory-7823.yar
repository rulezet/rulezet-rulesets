rule TTP_XOR_WriteProcessMemory_7823 {
  strings:
    $key_7823 = { 2f 51 [2] 1d 73 [2] 1b 46 [2] 35 46 [2] 0a 5a }

  condition:
    any of them
}