rule TTP_XOR_WriteProcessMemory_2f38 {
  strings:
    $key_2f38 = { 78 4a [2] 4a 68 [2] 4c 5d [2] 62 5d [2] 5d 41 }

  condition:
    any of them
}