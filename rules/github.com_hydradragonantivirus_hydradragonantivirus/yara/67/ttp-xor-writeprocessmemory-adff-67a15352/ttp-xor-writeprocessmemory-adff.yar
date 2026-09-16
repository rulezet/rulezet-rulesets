rule TTP_XOR_WriteProcessMemory_adff {
  strings:
    $key_adff = { fa 8d [2] c8 af [2] ce 9a [2] e0 9a [2] df 86 }

  condition:
    any of them
}