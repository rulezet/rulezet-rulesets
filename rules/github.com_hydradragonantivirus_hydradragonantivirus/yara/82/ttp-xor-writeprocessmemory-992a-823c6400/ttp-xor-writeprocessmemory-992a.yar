rule TTP_XOR_WriteProcessMemory_992a {
  strings:
    $key_992a = { ce 58 [2] fc 7a [2] fa 4f [2] d4 4f [2] eb 53 }

  condition:
    any of them
}