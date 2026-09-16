rule TTP_XOR_WriteProcessMemory_8318 {
  strings:
    $key_8318 = { d4 6a [2] e6 48 [2] e0 7d [2] ce 7d [2] f1 61 }

  condition:
    any of them
}