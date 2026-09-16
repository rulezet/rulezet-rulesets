rule TTP_XOR_WriteProcessMemory_97c6 {
  strings:
    $key_97c6 = { c0 b4 [2] f2 96 [2] f4 a3 [2] da a3 [2] e5 bf }

  condition:
    any of them
}