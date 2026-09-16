rule TTP_XOR_WriteProcessMemory_4bbe {
  strings:
    $key_4bbe = { 1c cc [2] 2e ee [2] 28 db [2] 06 db [2] 39 c7 }

  condition:
    any of them
}