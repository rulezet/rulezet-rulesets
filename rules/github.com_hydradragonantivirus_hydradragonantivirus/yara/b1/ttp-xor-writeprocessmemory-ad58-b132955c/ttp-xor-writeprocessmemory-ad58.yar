rule TTP_XOR_WriteProcessMemory_ad58 {
  strings:
    $key_ad58 = { fa 2a [2] c8 08 [2] ce 3d [2] e0 3d [2] df 21 }

  condition:
    any of them
}