rule TTP_XOR_WriteProcessMemory_ba1f {
  strings:
    $key_ba1f = { ed 6d [2] df 4f [2] d9 7a [2] f7 7a [2] c8 66 }

  condition:
    any of them
}