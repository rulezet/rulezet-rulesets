rule TTP_XOR_WriteProcessMemory_1e6d {
  strings:
    $key_1e6d = { 49 1f [2] 7b 3d [2] 7d 08 [2] 53 08 [2] 6c 14 }

  condition:
    any of them
}