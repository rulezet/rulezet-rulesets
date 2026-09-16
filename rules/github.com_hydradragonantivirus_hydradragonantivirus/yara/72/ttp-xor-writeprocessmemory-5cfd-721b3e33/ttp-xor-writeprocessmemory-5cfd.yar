rule TTP_XOR_WriteProcessMemory_5cfd {
  strings:
    $key_5cfd = { 0b 8f [2] 39 ad [2] 3f 98 [2] 11 98 [2] 2e 84 }

  condition:
    any of them
}