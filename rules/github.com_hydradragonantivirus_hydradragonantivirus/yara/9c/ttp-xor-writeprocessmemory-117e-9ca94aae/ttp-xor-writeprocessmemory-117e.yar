rule TTP_XOR_WriteProcessMemory_117e {
  strings:
    $key_117e = { 46 0c [2] 74 2e [2] 72 1b [2] 5c 1b [2] 63 07 }

  condition:
    any of them
}