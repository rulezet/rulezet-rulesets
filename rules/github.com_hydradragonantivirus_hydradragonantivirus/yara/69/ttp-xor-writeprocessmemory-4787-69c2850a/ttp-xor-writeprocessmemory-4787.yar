rule TTP_XOR_WriteProcessMemory_4787 {
  strings:
    $key_4787 = { 10 f5 [2] 22 d7 [2] 24 e2 [2] 0a e2 [2] 35 fe }

  condition:
    any of them
}