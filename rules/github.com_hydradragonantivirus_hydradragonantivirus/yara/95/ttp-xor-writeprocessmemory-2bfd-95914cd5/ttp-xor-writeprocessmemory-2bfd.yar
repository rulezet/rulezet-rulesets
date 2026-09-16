rule TTP_XOR_WriteProcessMemory_2bfd {
  strings:
    $key_2bfd = { 7c 8f [2] 4e ad [2] 48 98 [2] 66 98 [2] 59 84 }

  condition:
    any of them
}