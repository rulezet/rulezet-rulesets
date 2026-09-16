rule TTP_XOR_WriteProcessMemory_6ffd {
  strings:
    $key_6ffd = { 38 8f [2] 0a ad [2] 0c 98 [2] 22 98 [2] 1d 84 }

  condition:
    any of them
}