rule TTP_XOR_WriteProcessMemory_4138 {
  strings:
    $key_4138 = { 16 4a [2] 24 68 [2] 22 5d [2] 0c 5d [2] 33 41 }

  condition:
    any of them
}