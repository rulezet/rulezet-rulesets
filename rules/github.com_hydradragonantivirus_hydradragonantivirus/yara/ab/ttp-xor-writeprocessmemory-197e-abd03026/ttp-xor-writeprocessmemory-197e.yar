rule TTP_XOR_WriteProcessMemory_197e {
  strings:
    $key_197e = { 4e 0c [2] 7c 2e [2] 7a 1b [2] 54 1b [2] 6b 07 }

  condition:
    any of them
}