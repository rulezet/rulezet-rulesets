rule TTP_XOR_WriteProcessMemory_9d3c {
  strings:
    $key_9d3c = { ca 4e [2] f8 6c [2] fe 59 [2] d0 59 [2] ef 45 }

  condition:
    any of them
}