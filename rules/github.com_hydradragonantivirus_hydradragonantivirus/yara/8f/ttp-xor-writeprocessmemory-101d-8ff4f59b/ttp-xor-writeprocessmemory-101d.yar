rule TTP_XOR_WriteProcessMemory_101d {
  strings:
    $key_101d = { 47 6f [2] 75 4d [2] 73 78 [2] 5d 78 [2] 62 64 }

  condition:
    any of them
}