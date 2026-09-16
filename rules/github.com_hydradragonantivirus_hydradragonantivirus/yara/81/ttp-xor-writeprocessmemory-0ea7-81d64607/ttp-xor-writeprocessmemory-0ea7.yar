rule TTP_XOR_WriteProcessMemory_0ea7 {
  strings:
    $key_0ea7 = { 59 d5 [2] 6b f7 [2] 6d c2 [2] 43 c2 [2] 7c de }

  condition:
    any of them
}