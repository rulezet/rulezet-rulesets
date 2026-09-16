rule TTP_XOR_WriteProcessMemory_9bcb {
  strings:
    $key_9bcb = { cc b9 [2] fe 9b [2] f8 ae [2] d6 ae [2] e9 b2 }

  condition:
    any of them
}