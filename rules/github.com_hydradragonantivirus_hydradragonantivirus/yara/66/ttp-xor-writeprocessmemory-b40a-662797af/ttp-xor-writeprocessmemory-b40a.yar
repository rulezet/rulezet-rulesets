rule TTP_XOR_WriteProcessMemory_b40a {
  strings:
    $key_b40a = { e3 78 [2] d1 5a [2] d7 6f [2] f9 6f [2] c6 73 }

  condition:
    any of them
}