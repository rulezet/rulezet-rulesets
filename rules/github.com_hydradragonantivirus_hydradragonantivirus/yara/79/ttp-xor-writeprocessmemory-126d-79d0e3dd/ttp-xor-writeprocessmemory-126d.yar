rule TTP_XOR_WriteProcessMemory_126d {
  strings:
    $key_126d = { 45 1f [2] 77 3d [2] 71 08 [2] 5f 08 [2] 60 14 }

  condition:
    any of them
}