rule TTP_XOR_WriteProcessMemory_4747 {
  strings:
    $key_4747 = { 10 35 [2] 22 17 [2] 24 22 [2] 0a 22 [2] 35 3e }

  condition:
    any of them
}