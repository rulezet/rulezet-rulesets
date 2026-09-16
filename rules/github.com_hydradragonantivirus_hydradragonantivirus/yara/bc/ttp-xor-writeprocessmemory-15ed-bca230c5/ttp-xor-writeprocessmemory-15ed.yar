rule TTP_XOR_WriteProcessMemory_15ed {
  strings:
    $key_15ed = { 42 9f [2] 70 bd [2] 76 88 [2] 58 88 [2] 67 94 }

  condition:
    any of them
}