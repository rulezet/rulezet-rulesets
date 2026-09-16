rule TTP_XOR_WriteProcessMemory_3cfd {
  strings:
    $key_3cfd = { 6b 8f [2] 59 ad [2] 5f 98 [2] 71 98 [2] 4e 84 }

  condition:
    any of them
}