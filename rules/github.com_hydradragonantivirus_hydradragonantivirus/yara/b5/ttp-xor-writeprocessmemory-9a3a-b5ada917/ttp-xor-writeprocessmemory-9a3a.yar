rule TTP_XOR_WriteProcessMemory_9a3a {
  strings:
    $key_9a3a = { cd 48 [2] ff 6a [2] f9 5f [2] d7 5f [2] e8 43 }

  condition:
    any of them
}