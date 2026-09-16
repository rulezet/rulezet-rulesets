rule TTP_XOR_WriteProcessMemory_3e6d {
  strings:
    $key_3e6d = { 69 1f [2] 5b 3d [2] 5d 08 [2] 73 08 [2] 4c 14 }

  condition:
    any of them
}