rule TTP_XOR_WriteProcessMemory_85bf {
  strings:
    $key_85bf = { d2 cd [2] e0 ef [2] e6 da [2] c8 da [2] f7 c6 }

  condition:
    any of them
}