rule TTP_XOR_WriteProcessMemory_9d09 {
  strings:
    $key_9d09 = { ca 7b [2] f8 59 [2] fe 6c [2] d0 6c [2] ef 70 }

  condition:
    any of them
}