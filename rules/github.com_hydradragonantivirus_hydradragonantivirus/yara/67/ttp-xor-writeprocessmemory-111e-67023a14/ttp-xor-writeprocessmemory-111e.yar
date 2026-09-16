rule TTP_XOR_WriteProcessMemory_111e {
  strings:
    $key_111e = { 46 6c [2] 74 4e [2] 72 7b [2] 5c 7b [2] 63 67 }

  condition:
    any of them
}