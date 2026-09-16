rule TTP_XOR_WriteProcessMemory_1823 {
  strings:
    $key_1823 = { 4f 51 [2] 7d 73 [2] 7b 46 [2] 55 46 [2] 6a 5a }

  condition:
    any of them
}