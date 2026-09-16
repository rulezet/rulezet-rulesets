rule TTP_XOR_WriteProcessMemory_9195 {
  strings:
    $key_9195 = { c6 e7 [2] f4 c5 [2] f2 f0 [2] dc f0 [2] e3 ec }

  condition:
    any of them
}