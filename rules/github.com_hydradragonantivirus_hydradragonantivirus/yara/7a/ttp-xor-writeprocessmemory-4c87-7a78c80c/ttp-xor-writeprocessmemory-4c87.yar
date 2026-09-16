rule TTP_XOR_WriteProcessMemory_4c87 {
  strings:
    $key_4c87 = { 1b f5 [2] 29 d7 [2] 2f e2 [2] 01 e2 [2] 3e fe }

  condition:
    any of them
}