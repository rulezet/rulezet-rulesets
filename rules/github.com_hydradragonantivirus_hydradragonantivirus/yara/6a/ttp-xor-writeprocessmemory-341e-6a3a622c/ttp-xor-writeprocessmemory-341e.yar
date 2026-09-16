rule TTP_XOR_WriteProcessMemory_341e {
  strings:
    $key_341e = { 63 6c [2] 51 4e [2] 57 7b [2] 79 7b [2] 46 67 }

  condition:
    any of them
}