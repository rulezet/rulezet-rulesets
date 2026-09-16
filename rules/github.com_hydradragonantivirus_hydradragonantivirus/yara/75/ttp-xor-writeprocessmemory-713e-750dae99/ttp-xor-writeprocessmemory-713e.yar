rule TTP_XOR_WriteProcessMemory_713e {
  strings:
    $key_713e = { 26 4c [2] 14 6e [2] 12 5b [2] 3c 5b [2] 03 47 }

  condition:
    any of them
}