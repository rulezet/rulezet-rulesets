rule TTP_XOR_WriteProcessMemory_7dfd {
  strings:
    $key_7dfd = { 2a 8f [2] 18 ad [2] 1e 98 [2] 30 98 [2] 0f 84 }

  condition:
    any of them
}