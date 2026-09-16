rule TTP_XOR_WriteProcessMemory_972f {
  strings:
    $key_972f = { c0 5d [2] f2 7f [2] f4 4a [2] da 4a [2] e5 56 }

  condition:
    any of them
}