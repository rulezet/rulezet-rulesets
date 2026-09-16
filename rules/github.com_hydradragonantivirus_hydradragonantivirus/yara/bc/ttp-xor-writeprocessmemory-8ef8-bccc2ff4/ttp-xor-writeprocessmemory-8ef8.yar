rule TTP_XOR_WriteProcessMemory_8ef8 {
  strings:
    $key_8ef8 = { d9 8a [2] eb a8 [2] ed 9d [2] c3 9d [2] fc 81 }

  condition:
    any of them
}