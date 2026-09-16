rule TTP_XOR_WriteProcessMemory_b43c {
  strings:
    $key_b43c = { e3 4e [2] d1 6c [2] d7 59 [2] f9 59 [2] c6 45 }

  condition:
    any of them
}