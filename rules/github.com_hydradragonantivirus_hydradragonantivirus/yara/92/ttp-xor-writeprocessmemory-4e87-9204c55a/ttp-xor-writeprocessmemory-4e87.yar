rule TTP_XOR_WriteProcessMemory_4e87 {
  strings:
    $key_4e87 = { 19 f5 [2] 2b d7 [2] 2d e2 [2] 03 e2 [2] 3c fe }

  condition:
    any of them
}