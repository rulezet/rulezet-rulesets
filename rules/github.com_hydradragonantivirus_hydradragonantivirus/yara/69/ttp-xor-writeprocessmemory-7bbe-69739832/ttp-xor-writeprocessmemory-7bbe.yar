rule TTP_XOR_WriteProcessMemory_7bbe {
  strings:
    $key_7bbe = { 2c cc [2] 1e ee [2] 18 db [2] 36 db [2] 09 c7 }

  condition:
    any of them
}