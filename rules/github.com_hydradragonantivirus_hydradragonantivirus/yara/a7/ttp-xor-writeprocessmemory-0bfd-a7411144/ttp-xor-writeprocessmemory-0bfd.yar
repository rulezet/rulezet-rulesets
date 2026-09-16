rule TTP_XOR_WriteProcessMemory_0bfd {
  strings:
    $key_0bfd = { 5c 8f [2] 6e ad [2] 68 98 [2] 46 98 [2] 79 84 }

  condition:
    any of them
}