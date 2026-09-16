rule TTP_XOR_WriteProcessMemory_3ff5 {
  strings:
    $key_3ff5 = { 68 87 [2] 5a a5 [2] 5c 90 [2] 72 90 [2] 4d 8c }

  condition:
    any of them
}