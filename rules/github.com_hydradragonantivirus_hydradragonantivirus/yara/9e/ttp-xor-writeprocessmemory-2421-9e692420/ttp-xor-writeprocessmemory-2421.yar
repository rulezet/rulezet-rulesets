rule TTP_XOR_WriteProcessMemory_2421 {
  strings:
    $key_2421 = { 73 53 [2] 41 71 [2] 47 44 [2] 69 44 [2] 56 58 }

  condition:
    any of them
}