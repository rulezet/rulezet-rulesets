rule TTP_XOR_WriteProcessMemory_928a {
  strings:
    $key_928a = { c5 f8 [2] f7 da [2] f1 ef [2] df ef [2] e0 f3 }

  condition:
    any of them
}