rule TTP_XOR_WriteProcessMemory_310e {
  strings:
    $key_310e = { 66 7c [2] 54 5e [2] 52 6b [2] 7c 6b [2] 43 77 }

  condition:
    any of them
}