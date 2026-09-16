rule TTP_XOR_WriteProcessMemory_914b {
  strings:
    $key_914b = { c6 39 [2] f4 1b [2] f2 2e [2] dc 2e [2] e3 32 }

  condition:
    any of them
}