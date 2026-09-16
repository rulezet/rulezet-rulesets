rule TTP_XOR_WriteProcessMemory_5d86 {
  strings:
    $key_5d86 = { 0a f4 [2] 38 d6 [2] 3e e3 [2] 10 e3 [2] 2f ff }

  condition:
    any of them
}