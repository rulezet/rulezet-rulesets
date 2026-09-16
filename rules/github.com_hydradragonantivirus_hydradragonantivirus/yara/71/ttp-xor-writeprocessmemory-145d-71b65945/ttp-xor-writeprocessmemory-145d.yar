rule TTP_XOR_WriteProcessMemory_145d {
  strings:
    $key_145d = { 43 2f [2] 71 0d [2] 77 38 [2] 59 38 [2] 66 24 }

  condition:
    any of them
}