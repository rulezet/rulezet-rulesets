rule TTP_XOR_WriteProcessMemory_6962 {
  strings:
    $key_6962 = { 3e 10 [2] 0c 32 [2] 0a 07 [2] 24 07 [2] 1b 1b }

  condition:
    any of them
}