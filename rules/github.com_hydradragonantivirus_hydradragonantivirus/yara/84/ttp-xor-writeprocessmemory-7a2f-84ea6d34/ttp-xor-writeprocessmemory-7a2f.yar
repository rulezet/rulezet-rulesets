rule TTP_XOR_WriteProcessMemory_7a2f {
  strings:
    $key_7a2f = { 2d 5d [2] 1f 7f [2] 19 4a [2] 37 4a [2] 08 56 }

  condition:
    any of them
}