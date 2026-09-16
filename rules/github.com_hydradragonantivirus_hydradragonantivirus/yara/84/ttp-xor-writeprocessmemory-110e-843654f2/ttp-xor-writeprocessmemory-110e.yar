rule TTP_XOR_WriteProcessMemory_110e {
  strings:
    $key_110e = { 46 7c [2] 74 5e [2] 72 6b [2] 5c 6b [2] 63 77 }

  condition:
    any of them
}