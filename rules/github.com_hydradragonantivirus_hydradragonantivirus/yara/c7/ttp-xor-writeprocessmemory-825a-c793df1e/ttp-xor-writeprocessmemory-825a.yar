rule TTP_XOR_WriteProcessMemory_825a {
  strings:
    $key_825a = { d5 28 [2] e7 0a [2] e1 3f [2] cf 3f [2] f0 23 }

  condition:
    any of them
}