rule TTP_XOR_WriteProcessMemory_3e08 {
  strings:
    $key_3e08 = { 69 7a [2] 5b 58 [2] 5d 6d [2] 73 6d [2] 4c 71 }

  condition:
    any of them
}