rule TTP_XOR_WriteProcessMemory_176d {
  strings:
    $key_176d = { 40 1f [2] 72 3d [2] 74 08 [2] 5a 08 [2] 65 14 }

  condition:
    any of them
}