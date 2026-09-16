rule TTP_XOR_WriteProcessMemory_9dd3 {
  strings:
    $key_9dd3 = { ca a1 [2] f8 83 [2] fe b6 [2] d0 b6 [2] ef aa }

  condition:
    any of them
}