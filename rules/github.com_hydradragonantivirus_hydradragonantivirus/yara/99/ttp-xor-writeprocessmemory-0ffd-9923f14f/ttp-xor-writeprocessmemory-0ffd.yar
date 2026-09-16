rule TTP_XOR_WriteProcessMemory_0ffd {
  strings:
    $key_0ffd = { 58 8f [2] 6a ad [2] 6c 98 [2] 42 98 [2] 7d 84 }

  condition:
    any of them
}