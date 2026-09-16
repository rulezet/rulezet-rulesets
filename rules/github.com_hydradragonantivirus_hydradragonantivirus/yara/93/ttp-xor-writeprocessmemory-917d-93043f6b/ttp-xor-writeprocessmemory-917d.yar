rule TTP_XOR_WriteProcessMemory_917d {
  strings:
    $key_917d = { c6 0f [2] f4 2d [2] f2 18 [2] dc 18 [2] e3 04 }

  condition:
    any of them
}