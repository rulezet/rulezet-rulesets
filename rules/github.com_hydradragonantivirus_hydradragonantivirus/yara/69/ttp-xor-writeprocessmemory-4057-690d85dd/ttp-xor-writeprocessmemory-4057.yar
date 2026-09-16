rule TTP_XOR_WriteProcessMemory_4057 {
  strings:
    $key_4057 = { 17 25 [2] 25 07 [2] 23 32 [2] 0d 32 [2] 32 2e }

  condition:
    any of them
}