rule TTP_XOR_WriteProcessMemory_3574 {
  strings:
    $key_3574 = { 62 06 [2] 50 24 [2] 56 11 [2] 78 11 [2] 47 0d }

  condition:
    any of them
}