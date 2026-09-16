rule TTP_XOR_WriteProcessMemory_9c80 {
  strings:
    $key_9c80 = { cb f2 [2] f9 d0 [2] ff e5 [2] d1 e5 [2] ee f9 }

  condition:
    any of them
}