rule TTP_XOR_WriteProcessMemory_ba2f {
  strings:
    $key_ba2f = { ed 5d [2] df 7f [2] d9 4a [2] f7 4a [2] c8 56 }

  condition:
    any of them
}