rule TTP_XOR_WriteProcessMemory_9a5f {
  strings:
    $key_9a5f = { cd 2d [2] ff 0f [2] f9 3a [2] d7 3a [2] e8 26 }

  condition:
    any of them
}