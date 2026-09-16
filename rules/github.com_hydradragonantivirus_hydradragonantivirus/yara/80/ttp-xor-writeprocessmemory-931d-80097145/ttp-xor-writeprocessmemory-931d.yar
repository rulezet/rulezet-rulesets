rule TTP_XOR_WriteProcessMemory_931d {
  strings:
    $key_931d = { c4 6f [2] f6 4d [2] f0 78 [2] de 78 [2] e1 64 }

  condition:
    any of them
}