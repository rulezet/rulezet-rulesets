rule TTP_XOR_WriteProcessMemory_9a7a {
  strings:
    $key_9a7a = { cd 08 [2] ff 2a [2] f9 1f [2] d7 1f [2] e8 03 }

  condition:
    any of them
}