rule TTP_XOR_WriteProcessMemory_9c81 {
  strings:
    $key_9c81 = { cb f3 [2] f9 d1 [2] ff e4 [2] d1 e4 [2] ee f8 }

  condition:
    any of them
}