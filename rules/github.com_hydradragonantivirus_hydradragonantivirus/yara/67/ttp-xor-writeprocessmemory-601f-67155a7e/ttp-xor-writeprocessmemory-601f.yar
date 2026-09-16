rule TTP_XOR_WriteProcessMemory_601f {
  strings:
    $key_601f = { 37 6d [2] 05 4f [2] 03 7a [2] 2d 7a [2] 12 66 }

  condition:
    any of them
}