rule TTP_XOR_WriteProcessMemory_695e {
  strings:
    $key_695e = { 3e 2c [2] 0c 0e [2] 0a 3b [2] 24 3b [2] 1b 27 }

  condition:
    any of them
}