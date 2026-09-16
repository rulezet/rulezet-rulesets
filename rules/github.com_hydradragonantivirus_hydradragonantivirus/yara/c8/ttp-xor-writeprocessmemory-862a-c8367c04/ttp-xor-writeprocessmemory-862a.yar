rule TTP_XOR_WriteProcessMemory_862a {
  strings:
    $key_862a = { d1 58 [2] e3 7a [2] e5 4f [2] cb 4f [2] f4 53 }

  condition:
    any of them
}