rule TTP_XOR_WriteProcessMemory_6a5c {
  strings:
    $key_6a5c = { 3d 2e [2] 0f 0c [2] 09 39 [2] 27 39 [2] 18 25 }

  condition:
    any of them
}