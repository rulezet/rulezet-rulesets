rule TTP_XOR_WriteProcessMemory_1ef8 {
  strings:
    $key_1ef8 = { 49 8a [2] 7b a8 [2] 7d 9d [2] 53 9d [2] 6c 81 }

  condition:
    any of them
}