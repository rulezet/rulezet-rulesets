rule TTP_XOR_WriteProcessMemory_1f23 {
  strings:
    $key_1f23 = { 48 51 [2] 7a 73 [2] 7c 46 [2] 52 46 [2] 6d 5a }

  condition:
    any of them
}