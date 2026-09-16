rule TTP_XOR_WriteProcessMemory_410d {
  strings:
    $key_410d = { 16 7f [2] 24 5d [2] 22 68 [2] 0c 68 [2] 33 74 }

  condition:
    any of them
}