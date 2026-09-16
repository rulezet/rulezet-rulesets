rule TTP_XOR_WriteProcessMemory_9a4f {
  strings:
    $key_9a4f = { cd 3d [2] ff 1f [2] f9 2a [2] d7 2a [2] e8 36 }

  condition:
    any of them
}