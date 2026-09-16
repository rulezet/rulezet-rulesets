rule TTP_XOR_WriteProcessMemory_726d {
  strings:
    $key_726d = { 25 1f [2] 17 3d [2] 11 08 [2] 3f 08 [2] 00 14 }

  condition:
    any of them
}