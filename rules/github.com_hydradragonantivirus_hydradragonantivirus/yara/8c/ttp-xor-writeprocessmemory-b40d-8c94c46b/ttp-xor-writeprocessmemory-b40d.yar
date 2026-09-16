rule TTP_XOR_WriteProcessMemory_b40d {
  strings:
    $key_b40d = { e3 7f [2] d1 5d [2] d7 68 [2] f9 68 [2] c6 74 }

  condition:
    any of them
}