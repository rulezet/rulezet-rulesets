rule TTP_XOR_WriteProcessMemory_2c9c {
  strings:
    $key_2c9c = { 7b ee [2] 49 cc [2] 4f f9 [2] 61 f9 [2] 5e e5 }

  condition:
    any of them
}