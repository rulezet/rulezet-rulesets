rule TTP_XOR_WriteProcessMemory_106d {
  strings:
    $key_106d = { 47 1f [2] 75 3d [2] 73 08 [2] 5d 08 [2] 62 14 }

  condition:
    any of them
}