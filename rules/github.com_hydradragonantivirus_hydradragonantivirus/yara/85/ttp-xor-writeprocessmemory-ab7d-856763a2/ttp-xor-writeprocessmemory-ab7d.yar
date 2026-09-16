rule TTP_XOR_WriteProcessMemory_ab7d {
  strings:
    $key_ab7d = { fc 0f [2] ce 2d [2] c8 18 [2] e6 18 [2] d9 04 }

  condition:
    any of them
}