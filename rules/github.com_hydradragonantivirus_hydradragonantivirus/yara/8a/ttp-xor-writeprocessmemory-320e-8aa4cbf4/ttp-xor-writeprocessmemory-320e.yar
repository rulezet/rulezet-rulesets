rule TTP_XOR_WriteProcessMemory_320e {
  strings:
    $key_320e = { 65 7c [2] 57 5e [2] 51 6b [2] 7f 6b [2] 40 77 }

  condition:
    any of them
}