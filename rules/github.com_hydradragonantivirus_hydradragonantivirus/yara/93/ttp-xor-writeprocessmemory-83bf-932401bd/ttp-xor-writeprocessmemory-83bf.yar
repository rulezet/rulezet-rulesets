rule TTP_XOR_WriteProcessMemory_83bf {
  strings:
    $key_83bf = { d4 cd [2] e6 ef [2] e0 da [2] ce da [2] f1 c6 }

  condition:
    any of them
}