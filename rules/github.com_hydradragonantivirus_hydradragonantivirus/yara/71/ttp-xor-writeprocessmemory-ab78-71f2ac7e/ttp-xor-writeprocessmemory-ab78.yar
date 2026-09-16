rule TTP_XOR_WriteProcessMemory_ab78 {
  strings:
    $key_ab78 = { fc 0a [2] ce 28 [2] c8 1d [2] e6 1d [2] d9 01 }

  condition:
    any of them
}