rule TTP_XOR_WriteProcessMemory_6908 {
  strings:
    $key_6908 = { 3e 7a [2] 0c 58 [2] 0a 6d [2] 24 6d [2] 1b 71 }

  condition:
    any of them
}