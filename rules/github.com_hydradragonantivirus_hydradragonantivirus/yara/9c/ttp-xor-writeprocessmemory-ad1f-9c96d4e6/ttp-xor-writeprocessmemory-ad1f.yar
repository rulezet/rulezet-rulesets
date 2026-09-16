rule TTP_XOR_WriteProcessMemory_ad1f {
  strings:
    $key_ad1f = { fa 6d [2] c8 4f [2] ce 7a [2] e0 7a [2] df 66 }

  condition:
    any of them
}