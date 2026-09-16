rule TTP_XOR_WriteProcessMemory_3522 {
  strings:
    $key_3522 = { 62 50 [2] 50 72 [2] 56 47 [2] 78 47 [2] 47 5b }

  condition:
    any of them
}