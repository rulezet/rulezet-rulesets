rule TTP_XOR_WriteProcessMemory_6637 {
  strings:
    $key_6637 = { 31 45 [2] 03 67 [2] 05 52 [2] 2b 52 [2] 14 4e }

  condition:
    any of them
}