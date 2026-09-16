rule TTP_XOR_WriteProcessMemory_8e78 {
  strings:
    $key_8e78 = { d9 0a [2] eb 28 [2] ed 1d [2] c3 1d [2] fc 01 }

  condition:
    any of them
}