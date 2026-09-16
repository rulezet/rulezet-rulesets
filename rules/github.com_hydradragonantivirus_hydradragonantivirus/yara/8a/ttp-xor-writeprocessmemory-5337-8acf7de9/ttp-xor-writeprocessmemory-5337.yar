rule TTP_XOR_WriteProcessMemory_5337 {
  strings:
    $key_5337 = { 04 45 [2] 36 67 [2] 30 52 [2] 1e 52 [2] 21 4e }

  condition:
    any of them
}