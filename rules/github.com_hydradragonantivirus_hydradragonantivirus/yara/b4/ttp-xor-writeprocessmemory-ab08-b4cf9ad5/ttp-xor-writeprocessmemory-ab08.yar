rule TTP_XOR_WriteProcessMemory_ab08 {
  strings:
    $key_ab08 = { fc 7a [2] ce 58 [2] c8 6d [2] e6 6d [2] d9 71 }

  condition:
    any of them
}