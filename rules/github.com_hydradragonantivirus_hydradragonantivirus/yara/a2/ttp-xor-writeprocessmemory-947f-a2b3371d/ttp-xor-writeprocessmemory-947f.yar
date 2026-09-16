rule TTP_XOR_WriteProcessMemory_947f {
  strings:
    $key_947f = { c3 0d [2] f1 2f [2] f7 1a [2] d9 1a [2] e6 06 }

  condition:
    any of them
}