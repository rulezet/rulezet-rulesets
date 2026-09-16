rule TTP_XOR_WriteProcessMemory_bb44 {
  strings:
    $key_bb44 = { ec 36 [2] de 14 [2] d8 21 [2] f6 21 [2] c9 3d }

  condition:
    any of them
}