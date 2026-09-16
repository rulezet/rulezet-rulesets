rule TTP_XOR_WriteProcessMemory_9bdd {
  strings:
    $key_9bdd = { cc af [2] fe 8d [2] f8 b8 [2] d6 b8 [2] e9 a4 }

  condition:
    any of them
}