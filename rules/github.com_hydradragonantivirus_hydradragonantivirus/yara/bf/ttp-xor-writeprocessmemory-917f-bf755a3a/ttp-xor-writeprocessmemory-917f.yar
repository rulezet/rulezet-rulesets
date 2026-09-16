rule TTP_XOR_WriteProcessMemory_917f {
  strings:
    $key_917f = { c6 0d [2] f4 2f [2] f2 1a [2] dc 1a [2] e3 06 }

  condition:
    any of them
}