rule TTP_XOR_WriteProcessMemory_2b6d {
  strings:
    $key_2b6d = { 7c 1f [2] 4e 3d [2] 48 08 [2] 66 08 [2] 59 14 }

  condition:
    any of them
}