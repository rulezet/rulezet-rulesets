rule TTP_XOR_WriteProcessMemory_93bf {
  strings:
    $key_93bf = { c4 cd [2] f6 ef [2] f0 da [2] de da [2] e1 c6 }

  condition:
    any of them
}