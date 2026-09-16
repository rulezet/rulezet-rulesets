rule TTP_XOR_WriteProcessMemory_056d {
  strings:
    $key_056d = { 52 1f [2] 60 3d [2] 66 08 [2] 48 08 [2] 77 14 }

  condition:
    any of them
}