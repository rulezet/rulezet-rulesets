rule TTP_XOR_WriteProcessMemory_b8df {
  strings:
    $key_b8df = { ef ad [2] dd 8f [2] db ba [2] f5 ba [2] ca a6 }

  condition:
    any of them
}