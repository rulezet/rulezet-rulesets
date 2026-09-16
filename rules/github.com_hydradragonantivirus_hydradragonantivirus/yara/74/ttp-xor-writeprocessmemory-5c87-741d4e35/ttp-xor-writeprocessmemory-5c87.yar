rule TTP_XOR_WriteProcessMemory_5c87 {
  strings:
    $key_5c87 = { 0b f5 [2] 39 d7 [2] 3f e2 [2] 11 e2 [2] 2e fe }

  condition:
    any of them
}