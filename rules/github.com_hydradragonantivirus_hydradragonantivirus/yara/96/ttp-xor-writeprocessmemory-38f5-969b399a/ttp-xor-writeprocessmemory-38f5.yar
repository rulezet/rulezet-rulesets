rule TTP_XOR_WriteProcessMemory_38f5 {
  strings:
    $key_38f5 = { 6f 87 [2] 5d a5 [2] 5b 90 [2] 75 90 [2] 4a 8c }

  condition:
    any of them
}