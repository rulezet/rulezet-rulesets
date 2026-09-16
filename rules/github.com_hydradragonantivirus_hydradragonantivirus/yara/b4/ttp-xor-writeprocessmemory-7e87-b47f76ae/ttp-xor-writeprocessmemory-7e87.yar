rule TTP_XOR_WriteProcessMemory_7e87 {
  strings:
    $key_7e87 = { 29 f5 [2] 1b d7 [2] 1d e2 [2] 33 e2 [2] 0c fe }

  condition:
    any of them
}