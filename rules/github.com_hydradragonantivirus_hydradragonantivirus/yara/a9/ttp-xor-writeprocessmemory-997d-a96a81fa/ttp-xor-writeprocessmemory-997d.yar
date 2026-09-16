rule TTP_XOR_WriteProcessMemory_997d {
  strings:
    $key_997d = { ce 0f [2] fc 2d [2] fa 18 [2] d4 18 [2] eb 04 }

  condition:
    any of them
}