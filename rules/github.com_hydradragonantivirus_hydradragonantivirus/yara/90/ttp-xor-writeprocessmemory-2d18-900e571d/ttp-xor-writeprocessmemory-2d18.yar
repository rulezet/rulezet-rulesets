rule TTP_XOR_WriteProcessMemory_2d18 {
  strings:
    $key_2d18 = { 7a 6a [2] 48 48 [2] 4e 7d [2] 60 7d [2] 5f 61 }

  condition:
    any of them
}