rule TTP_XOR_WriteProcessMemory_fa87 {
  strings:
    $key_fa87 = { ad f5 [2] 9f d7 [2] 99 e2 [2] b7 e2 [2] 88 fe }

  condition:
    any of them
}