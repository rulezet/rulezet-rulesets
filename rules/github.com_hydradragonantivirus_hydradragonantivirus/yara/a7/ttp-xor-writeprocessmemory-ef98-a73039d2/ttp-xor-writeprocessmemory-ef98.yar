rule TTP_XOR_WriteProcessMemory_ef98 {
  strings:
    $key_ef98 = { b8 ea [2] 8a c8 [2] 8c fd [2] a2 fd [2] 9d e1 }

  condition:
    any of them
}