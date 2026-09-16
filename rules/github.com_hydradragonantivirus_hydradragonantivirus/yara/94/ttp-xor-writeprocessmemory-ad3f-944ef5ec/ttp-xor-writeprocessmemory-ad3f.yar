rule TTP_XOR_WriteProcessMemory_ad3f {
  strings:
    $key_ad3f = { fa 4d [2] c8 6f [2] ce 5a [2] e0 5a [2] df 46 }

  condition:
    any of them
}