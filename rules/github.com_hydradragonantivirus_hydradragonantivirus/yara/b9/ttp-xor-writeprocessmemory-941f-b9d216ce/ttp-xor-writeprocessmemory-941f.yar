rule TTP_XOR_WriteProcessMemory_941f {
  strings:
    $key_941f = { c3 6d [2] f1 4f [2] f7 7a [2] d9 7a [2] e6 66 }

  condition:
    any of them
}