rule TTP_XOR_WriteProcessMemory_582e {
  strings:
    $key_582e = { 0f 5c [2] 3d 7e [2] 3b 4b [2] 15 4b [2] 2a 57 }

  condition:
    any of them
}