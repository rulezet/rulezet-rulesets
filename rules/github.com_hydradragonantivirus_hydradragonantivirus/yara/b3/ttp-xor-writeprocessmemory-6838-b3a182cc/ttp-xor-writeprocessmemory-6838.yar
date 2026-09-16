rule TTP_XOR_WriteProcessMemory_6838 {
  strings:
    $key_6838 = { 3f 4a [2] 0d 68 [2] 0b 5d [2] 25 5d [2] 1a 41 }

  condition:
    any of them
}