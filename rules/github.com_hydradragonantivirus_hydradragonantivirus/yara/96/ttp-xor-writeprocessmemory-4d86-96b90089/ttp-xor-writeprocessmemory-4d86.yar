rule TTP_XOR_WriteProcessMemory_4d86 {
  strings:
    $key_4d86 = { 1a f4 [2] 28 d6 [2] 2e e3 [2] 00 e3 [2] 3f ff }

  condition:
    any of them
}