rule TTP_XOR_WriteProcessMemory_9ddc {
  strings:
    $key_9ddc = { ca ae [2] f8 8c [2] fe b9 [2] d0 b9 [2] ef a5 }

  condition:
    any of them
}