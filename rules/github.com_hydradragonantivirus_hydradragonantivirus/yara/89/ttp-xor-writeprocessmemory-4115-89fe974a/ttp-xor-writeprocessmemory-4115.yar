rule TTP_XOR_WriteProcessMemory_4115 {
  strings:
    $key_4115 = { 16 67 [2] 24 45 [2] 22 70 [2] 0c 70 [2] 33 6c }

  condition:
    any of them
}