rule TTP_XOR_WriteProcessMemory_280e {
  strings:
    $key_280e = { 7f 7c [2] 4d 5e [2] 4b 6b [2] 65 6b [2] 5a 77 }

  condition:
    any of them
}