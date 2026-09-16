rule TTP_XOR_WriteProcessMemory_1bfd {
  strings:
    $key_1bfd = { 4c 8f [2] 7e ad [2] 78 98 [2] 56 98 [2] 69 84 }

  condition:
    any of them
}