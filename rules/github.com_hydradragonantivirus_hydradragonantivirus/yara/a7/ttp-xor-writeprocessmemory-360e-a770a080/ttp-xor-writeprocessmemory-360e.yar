rule TTP_XOR_WriteProcessMemory_360e {
  strings:
    $key_360e = { 61 7c [2] 53 5e [2] 55 6b [2] 7b 6b [2] 44 77 }

  condition:
    any of them
}