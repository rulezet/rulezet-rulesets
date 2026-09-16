rule TTP_XOR_WriteProcessMemory_ad8a {
  strings:
    $key_ad8a = { fa f8 [2] c8 da [2] ce ef [2] e0 ef [2] df f3 }

  condition:
    any of them
}