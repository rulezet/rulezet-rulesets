rule TTP_XOR_WriteProcessMemory_611e {
  strings:
    $key_611e = { 36 6c [2] 04 4e [2] 02 7b [2] 2c 7b [2] 13 67 }

  condition:
    any of them
}