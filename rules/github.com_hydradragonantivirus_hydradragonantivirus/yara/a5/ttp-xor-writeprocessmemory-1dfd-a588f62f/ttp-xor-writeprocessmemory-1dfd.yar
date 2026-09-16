rule TTP_XOR_WriteProcessMemory_1dfd {
  strings:
    $key_1dfd = { 4a 8f [2] 78 ad [2] 7e 98 [2] 50 98 [2] 6f 84 }

  condition:
    any of them
}