rule TTP_XOR_WriteProcessMemory_940a {
  strings:
    $key_940a = { c3 78 [2] f1 5a [2] f7 6f [2] d9 6f [2] e6 73 }

  condition:
    any of them
}