rule TTP_XOR_WriteProcessMemory_4cfd {
  strings:
    $key_4cfd = { 1b 8f [2] 29 ad [2] 2f 98 [2] 01 98 [2] 3e 84 }

  condition:
    any of them
}