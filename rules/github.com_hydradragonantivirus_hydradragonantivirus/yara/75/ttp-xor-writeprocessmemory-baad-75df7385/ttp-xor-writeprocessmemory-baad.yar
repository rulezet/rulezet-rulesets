rule TTP_XOR_WriteProcessMemory_baad {
  strings:
    $key_baad = { ed df [2] df fd [2] d9 c8 [2] f7 c8 [2] c8 d4 }

  condition:
    any of them
}