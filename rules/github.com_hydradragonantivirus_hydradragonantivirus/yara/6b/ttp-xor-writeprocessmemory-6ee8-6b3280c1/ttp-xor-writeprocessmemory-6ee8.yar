rule TTP_XOR_WriteProcessMemory_6ee8 {
  strings:
    $key_6ee8 = { 39 9a [2] 0b b8 [2] 0d 8d [2] 23 8d [2] 1c 91 }

  condition:
    any of them
}