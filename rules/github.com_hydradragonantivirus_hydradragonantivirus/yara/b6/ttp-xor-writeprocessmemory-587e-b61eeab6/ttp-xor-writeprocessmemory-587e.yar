rule TTP_XOR_WriteProcessMemory_587e {
  strings:
    $key_587e = { 0f 0c [2] 3d 2e [2] 3b 1b [2] 15 1b [2] 2a 07 }

  condition:
    any of them
}