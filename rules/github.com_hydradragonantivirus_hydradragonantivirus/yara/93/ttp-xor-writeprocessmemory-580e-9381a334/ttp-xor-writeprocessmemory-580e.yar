rule TTP_XOR_WriteProcessMemory_580e {
  strings:
    $key_580e = { 0f 7c [2] 3d 5e [2] 3b 6b [2] 15 6b [2] 2a 77 }

  condition:
    any of them
}