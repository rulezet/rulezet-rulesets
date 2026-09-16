rule TTP_XOR_WriteProcessMemory_828a {
  strings:
    $key_828a = { d5 f8 [2] e7 da [2] e1 ef [2] cf ef [2] f0 f3 }

  condition:
    any of them
}