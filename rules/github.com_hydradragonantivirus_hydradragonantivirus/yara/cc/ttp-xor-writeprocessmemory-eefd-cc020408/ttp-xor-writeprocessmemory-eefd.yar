rule TTP_XOR_WriteProcessMemory_eefd {
  strings:
    $key_eefd = { b9 8f [2] 8b ad [2] 8d 98 [2] a3 98 [2] 9c 84 }

  condition:
    any of them
}