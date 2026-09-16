rule TTP_XOR_WriteProcessMemory_2fe8 {
  strings:
    $key_2fe8 = { 78 9a [2] 4a b8 [2] 4c 8d [2] 62 8d [2] 5d 91 }

  condition:
    any of them
}