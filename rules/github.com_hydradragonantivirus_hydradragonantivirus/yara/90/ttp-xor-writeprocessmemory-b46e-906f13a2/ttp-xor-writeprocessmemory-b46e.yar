rule TTP_XOR_WriteProcessMemory_b46e {
  strings:
    $key_b46e = { e3 1c [2] d1 3e [2] d7 0b [2] f9 0b [2] c6 17 }

  condition:
    any of them
}