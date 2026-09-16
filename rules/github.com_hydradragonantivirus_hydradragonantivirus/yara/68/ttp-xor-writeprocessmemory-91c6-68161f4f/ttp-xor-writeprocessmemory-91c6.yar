rule TTP_XOR_WriteProcessMemory_91c6 {
  strings:
    $key_91c6 = { c6 b4 [2] f4 96 [2] f2 a3 [2] dc a3 [2] e3 bf }

  condition:
    any of them
}