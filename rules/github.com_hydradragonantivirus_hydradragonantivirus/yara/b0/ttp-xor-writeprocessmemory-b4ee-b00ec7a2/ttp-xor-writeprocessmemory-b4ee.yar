rule TTP_XOR_WriteProcessMemory_b4ee {
  strings:
    $key_b4ee = { e3 9c [2] d1 be [2] d7 8b [2] f9 8b [2] c6 97 }

  condition:
    any of them
}