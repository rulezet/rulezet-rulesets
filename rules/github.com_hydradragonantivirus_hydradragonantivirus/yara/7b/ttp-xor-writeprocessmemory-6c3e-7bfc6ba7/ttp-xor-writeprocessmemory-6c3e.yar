rule TTP_XOR_WriteProcessMemory_6c3e {
  strings:
    $key_6c3e = { 3b 4c [2] 09 6e [2] 0f 5b [2] 21 5b [2] 1e 47 }

  condition:
    any of them
}