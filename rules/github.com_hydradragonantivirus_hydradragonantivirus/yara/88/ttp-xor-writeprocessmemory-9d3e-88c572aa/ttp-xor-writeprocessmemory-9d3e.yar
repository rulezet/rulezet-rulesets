rule TTP_XOR_WriteProcessMemory_9d3e {
  strings:
    $key_9d3e = { ca 4c [2] f8 6e [2] fe 5b [2] d0 5b [2] ef 47 }

  condition:
    any of them
}