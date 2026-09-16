rule TTP_XOR_WriteProcessMemory_9aca {
  strings:
    $key_9aca = { cd b8 [2] ff 9a [2] f9 af [2] d7 af [2] e8 b3 }

  condition:
    any of them
}