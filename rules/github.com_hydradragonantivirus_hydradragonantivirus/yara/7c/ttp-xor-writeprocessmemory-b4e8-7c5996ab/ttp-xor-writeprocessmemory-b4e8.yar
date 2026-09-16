rule TTP_XOR_WriteProcessMemory_b4e8 {
  strings:
    $key_b4e8 = { e3 9a [2] d1 b8 [2] d7 8d [2] f9 8d [2] c6 91 }

  condition:
    any of them
}