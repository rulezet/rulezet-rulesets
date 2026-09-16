rule TTP_XOR_WriteProcessMemory_6a4b {
  strings:
    $key_6a4b = { 3d 39 [2] 0f 1b [2] 09 2e [2] 27 2e [2] 18 32 }

  condition:
    any of them
}