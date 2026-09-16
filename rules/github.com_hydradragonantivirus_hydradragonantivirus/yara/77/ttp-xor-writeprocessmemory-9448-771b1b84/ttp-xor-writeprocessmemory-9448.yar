rule TTP_XOR_WriteProcessMemory_9448 {
  strings:
    $key_9448 = { c3 3a [2] f1 18 [2] f7 2d [2] d9 2d [2] e6 31 }

  condition:
    any of them
}