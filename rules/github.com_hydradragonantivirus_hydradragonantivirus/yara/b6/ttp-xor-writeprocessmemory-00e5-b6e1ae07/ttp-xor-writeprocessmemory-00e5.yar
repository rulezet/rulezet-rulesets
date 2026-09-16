rule TTP_XOR_WriteProcessMemory_00e5 {
  strings:
    $key_00e5 = { 57 97 [2] 65 b5 [2] 63 80 [2] 4d 80 [2] 72 9c }

  condition:
    any of them
}