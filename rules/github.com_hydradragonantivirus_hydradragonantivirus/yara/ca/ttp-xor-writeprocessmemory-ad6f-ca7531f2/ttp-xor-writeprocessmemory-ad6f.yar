rule TTP_XOR_WriteProcessMemory_ad6f {
  strings:
    $key_ad6f = { fa 1d [2] c8 3f [2] ce 0a [2] e0 0a [2] df 16 }

  condition:
    any of them
}