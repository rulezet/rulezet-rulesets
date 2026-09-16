rule TTP_XOR_WriteProcessMemory_7cfd {
  strings:
    $key_7cfd = { 2b 8f [2] 19 ad [2] 1f 98 [2] 31 98 [2] 0e 84 }

  condition:
    any of them
}