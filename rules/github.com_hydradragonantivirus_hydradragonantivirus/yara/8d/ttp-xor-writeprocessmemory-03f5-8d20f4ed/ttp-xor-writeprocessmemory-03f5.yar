rule TTP_XOR_WriteProcessMemory_03f5 {
  strings:
    $key_03f5 = { 54 87 [2] 66 a5 [2] 60 90 [2] 4e 90 [2] 71 8c }

  condition:
    any of them
}