rule TTP_XOR_WriteProcessMemory_e80e {
  strings:
    $key_e80e = { bf 7c [2] 8d 5e [2] 8b 6b [2] a5 6b [2] 9a 77 }

  condition:
    any of them
}