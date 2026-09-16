rule TTP_XOR_WriteProcessMemory_2fa6 {
  strings:
    $key_2fa6 = { 78 d4 [2] 4a f6 [2] 4c c3 [2] 62 c3 [2] 5d df }

  condition:
    any of them
}