rule TTP_XOR_WriteProcessMemory_31f5 {
  strings:
    $key_31f5 = { 66 87 [2] 54 a5 [2] 52 90 [2] 7c 90 [2] 43 8c }

  condition:
    any of them
}