rule TTP_XOR_WriteProcessMemory_ba7f {
  strings:
    $key_ba7f = { ed 0d [2] df 2f [2] d9 1a [2] f7 1a [2] c8 06 }

  condition:
    any of them
}