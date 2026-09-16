rule TTP_XOR_WriteProcessMemory_e015 {
  strings:
    $key_e015 = { b7 67 [2] 85 45 [2] 83 70 [2] ad 70 [2] 92 6c }

  condition:
    any of them
}