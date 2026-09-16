rule TTP_XOR_WriteProcessMemory_6e38 {
  strings:
    $key_6e38 = { 39 4a [2] 0b 68 [2] 0d 5d [2] 23 5d [2] 1c 41 }

  condition:
    any of them
}