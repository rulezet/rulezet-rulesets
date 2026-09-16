rule TTP_XOR_WriteProcessMemory_0330 {
  strings:
    $key_0330 = { 54 42 [2] 66 60 [2] 60 55 [2] 4e 55 [2] 71 49 }

  condition:
    any of them
}