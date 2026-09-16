rule TTP_XOR_WriteProcessMemory_9418 {
  strings:
    $key_9418 = { c3 6a [2] f1 48 [2] f7 7d [2] d9 7d [2] e6 61 }

  condition:
    any of them
}