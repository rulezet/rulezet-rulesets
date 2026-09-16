rule TTP_XOR_WriteProcessMemory_f86b {
  strings:
    $key_f86b = { af 19 [2] 9d 3b [2] 9b 0e [2] b5 0e [2] 8a 12 }

  condition:
    any of them
}