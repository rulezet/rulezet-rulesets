rule TTP_XOR_WriteProcessMemory_161d {
  strings:
    $key_161d = { 41 6f [2] 73 4d [2] 75 78 [2] 5b 78 [2] 64 64 }

  condition:
    any of them
}