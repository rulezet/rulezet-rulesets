rule TTP_XOR_WriteProcessMemory_083e {
  strings:
    $key_083e = { 5f 4c [2] 6d 6e [2] 6b 5b [2] 45 5b [2] 7a 47 }

  condition:
    any of them
}