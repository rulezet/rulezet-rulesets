rule TTP_XOR_WriteProcessMemory_0823 {
  strings:
    $key_0823 = { 5f 51 [2] 6d 73 [2] 6b 46 [2] 45 46 [2] 7a 5a }

  condition:
    any of them
}