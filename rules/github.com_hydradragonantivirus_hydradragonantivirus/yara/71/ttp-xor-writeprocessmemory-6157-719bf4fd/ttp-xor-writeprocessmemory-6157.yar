rule TTP_XOR_WriteProcessMemory_6157 {
  strings:
    $key_6157 = { 36 25 [2] 04 07 [2] 02 32 [2] 2c 32 [2] 13 2e }

  condition:
    any of them
}