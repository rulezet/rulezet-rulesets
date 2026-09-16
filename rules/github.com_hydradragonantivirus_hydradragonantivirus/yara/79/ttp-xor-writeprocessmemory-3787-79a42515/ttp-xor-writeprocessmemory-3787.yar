rule TTP_XOR_WriteProcessMemory_3787 {
  strings:
    $key_3787 = { 60 f5 [2] 52 d7 [2] 54 e2 [2] 7a e2 [2] 45 fe }

  condition:
    any of them
}