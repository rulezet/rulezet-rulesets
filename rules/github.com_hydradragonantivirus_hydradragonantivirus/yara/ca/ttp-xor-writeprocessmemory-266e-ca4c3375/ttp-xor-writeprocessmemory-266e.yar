rule TTP_XOR_WriteProcessMemory_266e {
  strings:
    $key_266e = { 71 1c [2] 43 3e [2] 45 0b [2] 6b 0b [2] 54 17 }

  condition:
    any of them
}