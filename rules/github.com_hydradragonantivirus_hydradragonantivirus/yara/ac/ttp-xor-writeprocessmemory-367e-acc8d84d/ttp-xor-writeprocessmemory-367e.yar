rule TTP_XOR_WriteProcessMemory_367e {
  strings:
    $key_367e = { 61 0c [2] 53 2e [2] 55 1b [2] 7b 1b [2] 44 07 }

  condition:
    any of them
}