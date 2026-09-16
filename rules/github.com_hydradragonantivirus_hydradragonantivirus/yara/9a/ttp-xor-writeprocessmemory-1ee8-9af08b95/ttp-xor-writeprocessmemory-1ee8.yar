rule TTP_XOR_WriteProcessMemory_1ee8 {
  strings:
    $key_1ee8 = { 49 9a [2] 7b b8 [2] 7d 8d [2] 53 8d [2] 6c 91 }

  condition:
    any of them
}