rule TTP_XOR_WriteProcessMemory_ad9c {
  strings:
    $key_ad9c = { fa ee [2] c8 cc [2] ce f9 [2] e0 f9 [2] df e5 }

  condition:
    any of them
}