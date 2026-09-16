rule TTP_XOR_WriteProcessMemory_10e8 {
  strings:
    $key_10e8 = { 47 9a [2] 75 b8 [2] 73 8d [2] 5d 8d [2] 62 91 }

  condition:
    any of them
}