rule TTP_XOR_WriteProcessMemory_7a3f {
  strings:
    $key_7a3f = { 2d 4d [2] 1f 6f [2] 19 5a [2] 37 5a [2] 08 46 }

  condition:
    any of them
}