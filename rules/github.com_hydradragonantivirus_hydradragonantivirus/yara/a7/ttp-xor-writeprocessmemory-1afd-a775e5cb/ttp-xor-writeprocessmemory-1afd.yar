rule TTP_XOR_WriteProcessMemory_1afd {
  strings:
    $key_1afd = { 4d 8f [2] 7f ad [2] 79 98 [2] 57 98 [2] 68 84 }

  condition:
    any of them
}