rule TTP_XOR_WriteProcessMemory_917b {
  strings:
    $key_917b = { c6 09 [2] f4 2b [2] f2 1e [2] dc 1e [2] e3 02 }

  condition:
    any of them
}