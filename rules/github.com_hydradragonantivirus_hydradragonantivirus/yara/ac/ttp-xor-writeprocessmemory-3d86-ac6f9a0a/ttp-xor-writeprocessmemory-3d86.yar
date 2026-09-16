rule TTP_XOR_WriteProcessMemory_3d86 {
  strings:
    $key_3d86 = { 6a f4 [2] 58 d6 [2] 5e e3 [2] 70 e3 [2] 4f ff }

  condition:
    any of them
}