rule TTP_XOR_WriteProcessMemory_3ef8 {
  strings:
    $key_3ef8 = { 69 8a [2] 5b a8 [2] 5d 9d [2] 73 9d [2] 4c 81 }

  condition:
    any of them
}