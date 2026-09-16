rule TTP_XOR_WriteProcessMemory_2efd {
  strings:
    $key_2efd = { 79 8f [2] 4b ad [2] 4d 98 [2] 63 98 [2] 5c 84 }

  condition:
    any of them
}