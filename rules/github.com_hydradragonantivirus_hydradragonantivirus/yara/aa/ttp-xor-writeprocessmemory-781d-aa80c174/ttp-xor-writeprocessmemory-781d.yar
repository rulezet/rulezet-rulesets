rule TTP_XOR_WriteProcessMemory_781d {
  strings:
    $key_781d = { 2f 6f [2] 1d 4d [2] 1b 78 [2] 35 78 [2] 0a 64 }

  condition:
    any of them
}