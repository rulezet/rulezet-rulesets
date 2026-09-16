rule TTP_XOR_WriteProcessMemory_baca {
  strings:
    $key_baca = { ed b8 [2] df 9a [2] d9 af [2] f7 af [2] c8 b3 }

  condition:
    any of them
}