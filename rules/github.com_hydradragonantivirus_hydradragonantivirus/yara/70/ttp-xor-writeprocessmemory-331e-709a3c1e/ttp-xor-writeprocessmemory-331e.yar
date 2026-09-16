rule TTP_XOR_WriteProcessMemory_331e {
  strings:
    $key_331e = { 64 6c [2] 56 4e [2] 50 7b [2] 7e 7b [2] 41 67 }

  condition:
    any of them
}