rule TTP_XOR_WriteProcessMemory_3d2e {
  strings:
    $key_3d2e = { 6a 5c [2] 58 7e [2] 5e 4b [2] 70 4b [2] 4f 57 }

  condition:
    any of them
}