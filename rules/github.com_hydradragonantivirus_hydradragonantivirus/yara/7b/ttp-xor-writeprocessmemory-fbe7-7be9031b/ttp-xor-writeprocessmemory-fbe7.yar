rule TTP_XOR_WriteProcessMemory_fbe7 {
  strings:
    $key_fbe7 = { ac 95 [2] 9e b7 [2] 98 82 [2] b6 82 [2] 89 9e }

  condition:
    any of them
}