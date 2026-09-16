rule TTP_XOR_WriteProcessMemory_080e {
  strings:
    $key_080e = { 5f 7c [2] 6d 5e [2] 6b 6b [2] 45 6b [2] 7a 77 }

  condition:
    any of them
}