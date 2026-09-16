rule TTP_XOR_WriteProcessMemory_948c {
  strings:
    $key_948c = { c3 fe [2] f1 dc [2] f7 e9 [2] d9 e9 [2] e6 f5 }

  condition:
    any of them
}