rule TTP_XOR_WriteProcessMemory_be9d {
  strings:
    $key_be9d = { e9 ef [2] db cd [2] dd f8 [2] f3 f8 [2] cc e4 }

  condition:
    any of them
}