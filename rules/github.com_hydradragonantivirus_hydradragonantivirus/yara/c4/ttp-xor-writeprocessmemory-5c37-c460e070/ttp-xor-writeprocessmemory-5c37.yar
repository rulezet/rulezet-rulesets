rule TTP_XOR_WriteProcessMemory_5c37 {
  strings:
    $key_5c37 = { 0b 45 [2] 39 67 [2] 3f 52 [2] 11 52 [2] 2e 4e }

  condition:
    any of them
}