rule TTP_XOR_WriteProcessMemory_396d {
  strings:
    $key_396d = { 6e 1f [2] 5c 3d [2] 5a 08 [2] 74 08 [2] 4b 14 }

  condition:
    any of them
}