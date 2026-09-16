rule TTP_XOR_WriteProcessMemory_9a0f {
  strings:
    $key_9a0f = { cd 7d [2] ff 5f [2] f9 6a [2] d7 6a [2] e8 76 }

  condition:
    any of them
}