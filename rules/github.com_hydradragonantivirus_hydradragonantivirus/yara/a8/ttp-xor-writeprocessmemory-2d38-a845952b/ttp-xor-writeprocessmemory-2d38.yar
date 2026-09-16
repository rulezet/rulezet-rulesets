rule TTP_XOR_WriteProcessMemory_2d38 {
  strings:
    $key_2d38 = { 7a 4a [2] 48 68 [2] 4e 5d [2] 60 5d [2] 5f 41 }

  condition:
    any of them
}