rule TTP_XOR_WriteProcessMemory_f687 {
  strings:
    $key_f687 = { a1 f5 [2] 93 d7 [2] 95 e2 [2] bb e2 [2] 84 fe }

  condition:
    any of them
}