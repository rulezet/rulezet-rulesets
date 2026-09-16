rule TTP_XOR_WriteProcessMemory_9a4d {
  strings:
    $key_9a4d = { cd 3f [2] ff 1d [2] f9 28 [2] d7 28 [2] e8 34 }

  condition:
    any of them
}