rule TTP_XOR_WriteProcessMemory_bafc {
  strings:
    $key_bafc = { ed 8e [2] df ac [2] d9 99 [2] f7 99 [2] c8 85 }

  condition:
    any of them
}