rule TTP_XOR_WriteProcessMemory_3bfd {
  strings:
    $key_3bfd = { 6c 8f [2] 5e ad [2] 58 98 [2] 76 98 [2] 49 84 }

  condition:
    any of them
}