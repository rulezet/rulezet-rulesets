rule TTP_XOR_WriteProcessMemory_2dfd {
  strings:
    $key_2dfd = { 7a 8f [2] 48 ad [2] 4e 98 [2] 60 98 [2] 5f 84 }

  condition:
    any of them
}