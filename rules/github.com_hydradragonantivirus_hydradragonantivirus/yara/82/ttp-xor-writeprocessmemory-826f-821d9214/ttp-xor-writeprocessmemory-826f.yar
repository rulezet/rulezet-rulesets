rule TTP_XOR_WriteProcessMemory_826f {
  strings:
    $key_826f = { d5 1d [2] e7 3f [2] e1 0a [2] cf 0a [2] f0 16 }

  condition:
    any of them
}