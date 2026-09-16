rule TTP_XOR_WriteProcessMemory_4afd {
  strings:
    $key_4afd = { 1d 8f [2] 2f ad [2] 29 98 [2] 07 98 [2] 38 84 }

  condition:
    any of them
}