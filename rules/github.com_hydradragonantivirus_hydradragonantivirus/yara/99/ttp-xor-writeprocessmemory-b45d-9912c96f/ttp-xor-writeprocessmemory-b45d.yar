rule TTP_XOR_WriteProcessMemory_b45d {
  strings:
    $key_b45d = { e3 2f [2] d1 0d [2] d7 38 [2] f9 38 [2] c6 24 }

  condition:
    any of them
}