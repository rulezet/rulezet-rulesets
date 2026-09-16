rule TTP_XOR_WriteProcessMemory_93c6 {
  strings:
    $key_93c6 = { c4 b4 [2] f6 96 [2] f0 a3 [2] de a3 [2] e1 bf }

  condition:
    any of them
}