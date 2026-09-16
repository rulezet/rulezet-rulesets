rule TTP_XOR_WriteProcessMemory_3698 {
  strings:
    $key_3698 = { 61 ea [2] 53 c8 [2] 55 fd [2] 7b fd [2] 44 e1 }

  condition:
    any of them
}