rule TTP_XOR_WriteProcessMemory_330e {
  strings:
    $key_330e = { 64 7c [2] 56 5e [2] 50 6b [2] 7e 6b [2] 41 77 }

  condition:
    any of them
}