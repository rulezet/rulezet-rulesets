rule TTP_XOR_WriteProcessMemory_605a {
  strings:
    $key_605a = { 37 28 [2] 05 0a [2] 03 3f [2] 2d 3f [2] 12 23 }

  condition:
    any of them
}