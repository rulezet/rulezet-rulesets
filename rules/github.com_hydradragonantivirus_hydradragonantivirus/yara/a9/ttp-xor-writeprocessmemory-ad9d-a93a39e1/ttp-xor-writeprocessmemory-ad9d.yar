rule TTP_XOR_WriteProcessMemory_ad9d {
  strings:
    $key_ad9d = { fa ef [2] c8 cd [2] ce f8 [2] e0 f8 [2] df e4 }

  condition:
    any of them
}