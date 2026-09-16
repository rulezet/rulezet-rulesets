rule TTP_XOR_WriteProcessMemory_807a {
  strings:
    $key_807a = { d7 08 [2] e5 2a [2] e3 1f [2] cd 1f [2] f2 03 }

  condition:
    any of them
}