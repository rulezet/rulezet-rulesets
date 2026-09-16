rule TTP_XOR_WriteProcessMemory_1efd {
  strings:
    $key_1efd = { 49 8f [2] 7b ad [2] 7d 98 [2] 53 98 [2] 6c 84 }

  condition:
    any of them
}