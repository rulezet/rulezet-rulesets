rule TTP_XOR_WriteProcessMemory_2e87 {
  strings:
    $key_2e87 = { 79 f5 [2] 4b d7 [2] 4d e2 [2] 63 e2 [2] 5c fe }

  condition:
    any of them
}