rule TTP_XOR_WriteProcessMemory_267e {
  strings:
    $key_267e = { 71 0c [2] 43 2e [2] 45 1b [2] 6b 1b [2] 54 07 }

  condition:
    any of them
}