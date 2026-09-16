rule TTP_XOR_WriteProcessMemory_b079 {
  strings:
    $key_b079 = { e7 0b [2] d5 29 [2] d3 1c [2] fd 1c [2] c2 00 }

  condition:
    any of them
}