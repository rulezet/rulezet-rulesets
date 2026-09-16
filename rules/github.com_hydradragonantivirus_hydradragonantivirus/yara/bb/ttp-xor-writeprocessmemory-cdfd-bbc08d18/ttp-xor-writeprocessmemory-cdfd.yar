rule TTP_XOR_WriteProcessMemory_cdfd {
  strings:
    $key_cdfd = { 9a 8f [2] a8 ad [2] ae 98 [2] 80 98 [2] bf 84 }

  condition:
    any of them
}