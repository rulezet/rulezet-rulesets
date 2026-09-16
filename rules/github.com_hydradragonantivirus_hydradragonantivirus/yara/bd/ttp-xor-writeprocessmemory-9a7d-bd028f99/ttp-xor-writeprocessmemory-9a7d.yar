rule TTP_XOR_WriteProcessMemory_9a7d {
  strings:
    $key_9a7d = { cd 0f [2] ff 2d [2] f9 18 [2] d7 18 [2] e8 04 }

  condition:
    any of them
}