rule TTP_XOR_WriteProcessMemory_ba3d {
  strings:
    $key_ba3d = { ed 4f [2] df 6d [2] d9 58 [2] f7 58 [2] c8 44 }

  condition:
    any of them
}