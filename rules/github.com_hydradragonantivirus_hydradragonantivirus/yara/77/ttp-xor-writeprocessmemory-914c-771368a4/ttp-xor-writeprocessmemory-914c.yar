rule TTP_XOR_WriteProcessMemory_914c {
  strings:
    $key_914c = { c6 3e [2] f4 1c [2] f2 29 [2] dc 29 [2] e3 35 }

  condition:
    any of them
}