rule TTP_XOR_WriteProcessMemory_9a2f {
  strings:
    $key_9a2f = { cd 5d [2] ff 7f [2] f9 4a [2] d7 4a [2] e8 56 }

  condition:
    any of them
}