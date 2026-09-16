rule TTP_XOR_WriteProcessMemory_767e {
  strings:
    $key_767e = { 21 0c [2] 13 2e [2] 15 1b [2] 3b 1b [2] 04 07 }

  condition:
    any of them
}