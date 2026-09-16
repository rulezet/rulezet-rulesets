rule TTP_XOR_WriteProcessMemory_6f38 {
  strings:
    $key_6f38 = { 38 4a [2] 0a 68 [2] 0c 5d [2] 22 5d [2] 1d 41 }

  condition:
    any of them
}