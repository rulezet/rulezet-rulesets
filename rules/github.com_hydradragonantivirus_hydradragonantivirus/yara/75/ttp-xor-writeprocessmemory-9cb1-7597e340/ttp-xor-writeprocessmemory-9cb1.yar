rule TTP_XOR_WriteProcessMemory_9cb1 {
  strings:
    $key_9cb1 = { cb c3 [2] f9 e1 [2] ff d4 [2] d1 d4 [2] ee c8 }

  condition:
    any of them
}