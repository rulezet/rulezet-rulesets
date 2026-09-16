rule TTP_XOR_WriteProcessMemory_9dbf {
  strings:
    $key_9dbf = { ca cd [2] f8 ef [2] fe da [2] d0 da [2] ef c6 }

  condition:
    any of them
}