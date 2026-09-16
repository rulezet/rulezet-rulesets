rule TTP_XOR_WriteProcessMemory_b47a {
  strings:
    $key_b47a = { e3 08 [2] d1 2a [2] d7 1f [2] f9 1f [2] c6 03 }

  condition:
    any of them
}