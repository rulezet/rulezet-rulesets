rule TTP_XOR_WriteProcessMemory_ed80 {
  strings:
    $key_ed80 = { ba f2 [2] 88 d0 [2] 8e e5 [2] a0 e5 [2] 9f f9 }

  condition:
    any of them
}