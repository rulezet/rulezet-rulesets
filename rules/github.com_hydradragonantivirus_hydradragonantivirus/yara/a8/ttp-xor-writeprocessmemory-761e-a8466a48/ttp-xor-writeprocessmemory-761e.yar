rule TTP_XOR_WriteProcessMemory_761e {
  strings:
    $key_761e = { 21 6c [2] 13 4e [2] 15 7b [2] 3b 7b [2] 04 67 }

  condition:
    any of them
}