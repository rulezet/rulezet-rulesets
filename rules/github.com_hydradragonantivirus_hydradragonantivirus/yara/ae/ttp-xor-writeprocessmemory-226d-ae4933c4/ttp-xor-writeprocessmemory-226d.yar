rule TTP_XOR_WriteProcessMemory_226d {
  strings:
    $key_226d = { 75 1f [2] 47 3d [2] 41 08 [2] 6f 08 [2] 50 14 }

  condition:
    any of them
}