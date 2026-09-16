rule TTP_XOR_WriteProcessMemory_9c95 {
  strings:
    $key_9c95 = { cb e7 [2] f9 c5 [2] ff f0 [2] d1 f0 [2] ee ec }

  condition:
    any of them
}