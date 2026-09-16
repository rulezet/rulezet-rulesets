rule TTP_XOR_WriteProcessMemory_bd0e {
  strings:
    $key_bd0e = { ea 7c [2] d8 5e [2] de 6b [2] f0 6b [2] cf 77 }

  condition:
    any of them
}