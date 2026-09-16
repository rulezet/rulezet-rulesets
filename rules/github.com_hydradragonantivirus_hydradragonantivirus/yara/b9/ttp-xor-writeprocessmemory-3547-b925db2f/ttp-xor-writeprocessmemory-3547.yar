rule TTP_XOR_WriteProcessMemory_3547 {
  strings:
    $key_3547 = { 62 35 [2] 50 17 [2] 56 22 [2] 78 22 [2] 47 3e }

  condition:
    any of them
}