rule TTP_XOR_WriteProcessMemory_3325 {
  strings:
    $key_3325 = { 64 57 [2] 56 75 [2] 50 40 [2] 7e 40 [2] 41 5c }

  condition:
    any of them
}