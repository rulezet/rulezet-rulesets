rule TTP_XOR_WriteProcessMemory_2ffd {
  strings:
    $key_2ffd = { 78 8f [2] 4a ad [2] 4c 98 [2] 62 98 [2] 5d 84 }

  condition:
    any of them
}