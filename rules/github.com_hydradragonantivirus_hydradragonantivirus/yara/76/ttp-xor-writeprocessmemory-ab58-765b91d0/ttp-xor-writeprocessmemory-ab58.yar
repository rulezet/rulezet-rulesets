rule TTP_XOR_WriteProcessMemory_ab58 {
  strings:
    $key_ab58 = { fc 2a [2] ce 08 [2] c8 3d [2] e6 3d [2] d9 21 }

  condition:
    any of them
}