rule TTP_XOR_WriteProcessMemory_7a6c {
  strings:
    $key_7a6c = { 2d 1e [2] 1f 3c [2] 19 09 [2] 37 09 [2] 08 15 }

  condition:
    any of them
}