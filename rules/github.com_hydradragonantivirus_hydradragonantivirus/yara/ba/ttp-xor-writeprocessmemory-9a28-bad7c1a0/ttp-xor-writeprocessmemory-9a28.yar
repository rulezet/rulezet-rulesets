rule TTP_XOR_WriteProcessMemory_9a28 {
  strings:
    $key_9a28 = { cd 5a [2] ff 78 [2] f9 4d [2] d7 4d [2] e8 51 }

  condition:
    any of them
}