rule TTP_XOR_WriteProcessMemory_3b37 {
  strings:
    $key_3b37 = { 6c 45 [2] 5e 67 [2] 58 52 [2] 76 52 [2] 49 4e }

  condition:
    any of them
}