rule TTP_XOR_WriteProcessMemory_4efd {
  strings:
    $key_4efd = { 19 8f [2] 2b ad [2] 2d 98 [2] 03 98 [2] 3c 84 }

  condition:
    any of them
}