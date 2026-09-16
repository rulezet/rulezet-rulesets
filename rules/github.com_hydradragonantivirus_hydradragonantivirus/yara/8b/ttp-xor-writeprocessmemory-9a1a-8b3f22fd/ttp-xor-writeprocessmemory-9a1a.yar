rule TTP_XOR_WriteProcessMemory_9a1a {
  strings:
    $key_9a1a = { cd 68 [2] ff 4a [2] f9 7f [2] d7 7f [2] e8 63 }

  condition:
    any of them
}