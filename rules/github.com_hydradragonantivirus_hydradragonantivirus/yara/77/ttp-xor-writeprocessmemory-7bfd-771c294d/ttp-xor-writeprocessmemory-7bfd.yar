rule TTP_XOR_WriteProcessMemory_7bfd {
  strings:
    $key_7bfd = { 2c 8f [2] 1e ad [2] 18 98 [2] 36 98 [2] 09 84 }

  condition:
    any of them
}