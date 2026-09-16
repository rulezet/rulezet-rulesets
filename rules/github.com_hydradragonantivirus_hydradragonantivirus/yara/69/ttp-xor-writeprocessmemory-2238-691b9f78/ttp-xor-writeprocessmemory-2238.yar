rule TTP_XOR_WriteProcessMemory_2238 {
  strings:
    $key_2238 = { 75 4a [2] 47 68 [2] 41 5d [2] 6f 5d [2] 50 41 }

  condition:
    any of them
}