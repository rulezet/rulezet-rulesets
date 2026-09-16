rule TTP_XOR_WriteProcessMemory_7d23 {
  strings:
    $key_7d23 = { 2a 51 [2] 18 73 [2] 1e 46 [2] 30 46 [2] 0f 5a }

  condition:
    any of them
}