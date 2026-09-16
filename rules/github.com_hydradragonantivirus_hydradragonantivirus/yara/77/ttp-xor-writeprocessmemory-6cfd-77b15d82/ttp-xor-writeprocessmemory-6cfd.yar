rule TTP_XOR_WriteProcessMemory_6cfd {
  strings:
    $key_6cfd = { 3b 8f [2] 09 ad [2] 0f 98 [2] 21 98 [2] 1e 84 }

  condition:
    any of them
}