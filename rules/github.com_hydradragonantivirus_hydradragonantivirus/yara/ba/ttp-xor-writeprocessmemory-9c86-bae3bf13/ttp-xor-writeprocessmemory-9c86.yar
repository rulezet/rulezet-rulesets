rule TTP_XOR_WriteProcessMemory_9c86 {
  strings:
    $key_9c86 = { cb f4 [2] f9 d6 [2] ff e3 [2] d1 e3 [2] ee ff }

  condition:
    any of them
}