rule TTP_XOR_WriteProcessMemory_935a {
  strings:
    $key_935a = { c4 28 [2] f6 0a [2] f0 3f [2] de 3f [2] e1 23 }

  condition:
    any of them
}