rule TTP_XOR_WriteProcessMemory_7ee8 {
  strings:
    $key_7ee8 = { 29 9a [2] 1b b8 [2] 1d 8d [2] 33 8d [2] 0c 91 }

  condition:
    any of them
}