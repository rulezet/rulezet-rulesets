rule TTP_XOR_WriteProcessMemory_9a18 {
  strings:
    $key_9a18 = { cd 6a [2] ff 48 [2] f9 7d [2] d7 7d [2] e8 61 }

  condition:
    any of them
}