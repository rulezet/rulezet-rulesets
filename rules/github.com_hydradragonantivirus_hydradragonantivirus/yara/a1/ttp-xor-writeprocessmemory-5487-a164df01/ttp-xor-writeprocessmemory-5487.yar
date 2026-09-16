rule TTP_XOR_WriteProcessMemory_5487 {
  strings:
    $key_5487 = { 03 f5 [2] 31 d7 [2] 37 e2 [2] 19 e2 [2] 26 fe }

  condition:
    any of them
}