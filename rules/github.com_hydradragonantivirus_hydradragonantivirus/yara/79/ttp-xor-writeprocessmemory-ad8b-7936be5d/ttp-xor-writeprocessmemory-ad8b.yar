rule TTP_XOR_WriteProcessMemory_ad8b {
  strings:
    $key_ad8b = { fa f9 [2] c8 db [2] ce ee [2] e0 ee [2] df f2 }

  condition:
    any of them
}