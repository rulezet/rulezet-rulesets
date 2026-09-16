rule TTP_XOR_WriteProcessMemory_4b6d {
  strings:
    $key_4b6d = { 1c 1f [2] 2e 3d [2] 28 08 [2] 06 08 [2] 39 14 }

  condition:
    any of them
}