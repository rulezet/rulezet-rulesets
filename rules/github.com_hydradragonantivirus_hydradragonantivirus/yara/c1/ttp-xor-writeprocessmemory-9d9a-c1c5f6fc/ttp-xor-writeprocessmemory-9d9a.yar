rule TTP_XOR_WriteProcessMemory_9d9a {
  strings:
    $key_9d9a = { ca e8 [2] f8 ca [2] fe ff [2] d0 ff [2] ef e3 }

  condition:
    any of them
}