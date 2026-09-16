rule TTP_XOR_WriteProcessMemory_7857 {
  strings:
    $key_7857 = { 2f 25 [2] 1d 07 [2] 1b 32 [2] 35 32 [2] 0a 2e }

  condition:
    any of them
}