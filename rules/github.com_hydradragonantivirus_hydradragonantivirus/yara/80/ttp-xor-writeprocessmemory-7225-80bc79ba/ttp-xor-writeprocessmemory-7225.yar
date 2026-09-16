rule TTP_XOR_WriteProcessMemory_7225 {
  strings:
    $key_7225 = { 25 57 [2] 17 75 [2] 11 40 [2] 3f 40 [2] 00 5c }

  condition:
    any of them
}