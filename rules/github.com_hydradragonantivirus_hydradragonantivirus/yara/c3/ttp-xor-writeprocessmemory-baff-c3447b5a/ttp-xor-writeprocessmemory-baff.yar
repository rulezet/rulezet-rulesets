rule TTP_XOR_WriteProcessMemory_baff {
  strings:
    $key_baff = { ed 8d [2] df af [2] d9 9a [2] f7 9a [2] c8 86 }

  condition:
    any of them
}