rule TTP_XOR_WriteProcessMemory_0dfd {
  strings:
    $key_0dfd = { 5a 8f [2] 68 ad [2] 6e 98 [2] 40 98 [2] 7f 84 }

  condition:
    any of them
}