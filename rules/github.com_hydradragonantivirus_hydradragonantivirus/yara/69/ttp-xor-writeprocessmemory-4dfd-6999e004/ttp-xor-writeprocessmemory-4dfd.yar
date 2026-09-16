rule TTP_XOR_WriteProcessMemory_4dfd {
  strings:
    $key_4dfd = { 1a 8f [2] 28 ad [2] 2e 98 [2] 00 98 [2] 3f 84 }

  condition:
    any of them
}