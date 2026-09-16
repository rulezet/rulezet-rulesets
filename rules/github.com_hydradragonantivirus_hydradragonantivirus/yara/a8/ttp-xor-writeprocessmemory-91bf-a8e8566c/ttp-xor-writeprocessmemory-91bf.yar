rule TTP_XOR_WriteProcessMemory_91bf {
  strings:
    $key_91bf = { c6 cd [2] f4 ef [2] f2 da [2] dc da [2] e3 c6 }

  condition:
    any of them
}