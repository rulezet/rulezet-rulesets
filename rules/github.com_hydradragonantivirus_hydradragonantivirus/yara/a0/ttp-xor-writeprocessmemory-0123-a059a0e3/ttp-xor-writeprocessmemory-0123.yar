rule TTP_XOR_WriteProcessMemory_0123 {
  strings:
    $key_0123 = { 56 51 [2] 64 73 [2] 62 46 [2] 4c 46 [2] 73 5a }

  condition:
    any of them
}