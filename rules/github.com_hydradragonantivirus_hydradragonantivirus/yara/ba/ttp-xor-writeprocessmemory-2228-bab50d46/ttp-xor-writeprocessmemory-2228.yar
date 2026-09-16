rule TTP_XOR_WriteProcessMemory_2228 {
  strings:
    $key_2228 = { 75 5a [2] 47 78 [2] 41 4d [2] 6f 4d [2] 50 51 }

  condition:
    any of them
}