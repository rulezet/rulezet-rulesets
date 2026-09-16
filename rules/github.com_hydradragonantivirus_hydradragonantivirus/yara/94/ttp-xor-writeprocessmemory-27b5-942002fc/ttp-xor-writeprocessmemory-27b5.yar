rule TTP_XOR_WriteProcessMemory_27b5 {
  strings:
    $key_27b5 = { 70 c7 [2] 42 e5 [2] 44 d0 [2] 6a d0 [2] 55 cc }

  condition:
    any of them
}