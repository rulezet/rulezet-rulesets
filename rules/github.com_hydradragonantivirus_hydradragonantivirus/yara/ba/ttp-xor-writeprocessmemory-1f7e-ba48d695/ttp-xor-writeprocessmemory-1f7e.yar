rule TTP_XOR_WriteProcessMemory_1f7e {
  strings:
    $key_1f7e = { 48 0c [2] 7a 2e [2] 7c 1b [2] 52 1b [2] 6d 07 }

  condition:
    any of them
}