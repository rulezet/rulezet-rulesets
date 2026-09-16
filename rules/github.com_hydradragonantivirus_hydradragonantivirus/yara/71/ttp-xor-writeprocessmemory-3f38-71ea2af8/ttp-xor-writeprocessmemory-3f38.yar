rule TTP_XOR_WriteProcessMemory_3f38 {
  strings:
    $key_3f38 = { 68 4a [2] 5a 68 [2] 5c 5d [2] 72 5d [2] 4d 41 }

  condition:
    any of them
}