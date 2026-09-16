rule TTP_XOR_WriteProcessMemory_9495 {
  strings:
    $key_9495 = { c3 e7 [2] f1 c5 [2] f7 f0 [2] d9 f0 [2] e6 ec }

  condition:
    any of them
}