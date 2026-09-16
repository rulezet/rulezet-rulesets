rule TTP_XOR_WriteProcessMemory_9dcb {
  strings:
    $key_9dcb = { ca b9 [2] f8 9b [2] fe ae [2] d0 ae [2] ef b2 }

  condition:
    any of them
}