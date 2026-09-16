rule TTP_XOR_WriteProcessMemory_4e1f {
  strings:
    $key_4e1f = { 19 6d [2] 2b 4f [2] 2d 7a [2] 03 7a [2] 3c 66 }

  condition:
    any of them
}