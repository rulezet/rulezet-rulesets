rule TTP_XOR_WriteProcessMemory_8e58 {
  strings:
    $key_8e58 = { d9 2a [2] eb 08 [2] ed 3d [2] c3 3d [2] fc 21 }

  condition:
    any of them
}