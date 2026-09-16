rule TTP_XOR_WriteProcessMemory_4042 {
  strings:
    $key_4042 = { 17 30 [2] 25 12 [2] 23 27 [2] 0d 27 [2] 32 3b }

  condition:
    any of them
}