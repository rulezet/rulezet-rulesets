rule TTP_XOR_WriteProcessMemory_9c8a {
  strings:
    $key_9c8a = { cb f8 [2] f9 da [2] ff ef [2] d1 ef [2] ee f3 }

  condition:
    any of them
}