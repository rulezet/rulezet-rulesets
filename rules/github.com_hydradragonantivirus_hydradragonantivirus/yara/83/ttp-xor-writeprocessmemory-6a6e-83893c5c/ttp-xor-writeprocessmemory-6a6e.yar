rule TTP_XOR_WriteProcessMemory_6a6e {
  strings:
    $key_6a6e = { 3d 1c [2] 0f 3e [2] 09 0b [2] 27 0b [2] 18 17 }

  condition:
    any of them
}