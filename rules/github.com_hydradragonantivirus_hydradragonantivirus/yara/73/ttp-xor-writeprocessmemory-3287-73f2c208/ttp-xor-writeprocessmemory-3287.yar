rule TTP_XOR_WriteProcessMemory_3287 {
  strings:
    $key_3287 = { 65 f5 [2] 57 d7 [2] 51 e2 [2] 7f e2 [2] 40 fe }

  condition:
    any of them
}