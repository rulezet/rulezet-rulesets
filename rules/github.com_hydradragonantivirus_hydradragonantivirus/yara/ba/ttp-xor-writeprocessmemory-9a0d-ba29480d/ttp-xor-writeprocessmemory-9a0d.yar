rule TTP_XOR_WriteProcessMemory_9a0d {
  strings:
    $key_9a0d = { cd 7f [2] ff 5d [2] f9 68 [2] d7 68 [2] e8 74 }

  condition:
    any of them
}