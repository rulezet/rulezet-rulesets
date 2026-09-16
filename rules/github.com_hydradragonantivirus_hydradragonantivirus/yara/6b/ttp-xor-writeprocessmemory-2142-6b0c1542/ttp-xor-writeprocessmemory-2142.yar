rule TTP_XOR_WriteProcessMemory_2142 {
  strings:
    $key_2142 = { 76 30 [2] 44 12 [2] 42 27 [2] 6c 27 [2] 53 3b }

  condition:
    any of them
}