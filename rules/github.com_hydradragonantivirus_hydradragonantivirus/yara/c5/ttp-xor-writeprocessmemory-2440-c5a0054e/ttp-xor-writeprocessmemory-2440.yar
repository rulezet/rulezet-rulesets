rule TTP_XOR_WriteProcessMemory_2440 {
  strings:
    $key_2440 = { 73 32 [2] 41 10 [2] 47 25 [2] 69 25 [2] 56 39 }

  condition:
    any of them
}