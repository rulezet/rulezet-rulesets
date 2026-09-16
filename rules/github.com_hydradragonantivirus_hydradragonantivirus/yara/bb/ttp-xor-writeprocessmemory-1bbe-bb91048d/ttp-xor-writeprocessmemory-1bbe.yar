rule TTP_XOR_WriteProcessMemory_1bbe {
  strings:
    $key_1bbe = { 4c cc [2] 7e ee [2] 78 db [2] 56 db [2] 69 c7 }

  condition:
    any of them
}