rule TTP_XOR_WriteProcessMemory_908a {
  strings:
    $key_908a = { c7 f8 [2] f5 da [2] f3 ef [2] dd ef [2] e2 f3 }

  condition:
    any of them
}