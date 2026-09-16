rule TTP_XOR_WriteProcessMemory_adbf {
  strings:
    $key_adbf = { fa cd [2] c8 ef [2] ce da [2] e0 da [2] df c6 }

  condition:
    any of them
}