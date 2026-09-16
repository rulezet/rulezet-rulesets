rule TTP_XOR_WriteProcessMemory_6d86 {
  strings:
    $key_6d86 = { 3a f4 [2] 08 d6 [2] 0e e3 [2] 20 e3 [2] 1f ff }

  condition:
    any of them
}