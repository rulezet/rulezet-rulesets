rule TTP_XOR_WriteProcessMemory_6a0e {
  strings:
    $key_6a0e = { 3d 7c [2] 0f 5e [2] 09 6b [2] 27 6b [2] 18 77 }

  condition:
    any of them
}