rule TTP_XOR_WriteProcessMemory_347e {
  strings:
    $key_347e = { 63 0c [2] 51 2e [2] 57 1b [2] 79 1b [2] 46 07 }

  condition:
    any of them
}