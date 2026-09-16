rule TTP_XOR_WriteProcessMemory_007f {
  strings:
    $key_007f = { 57 0d [2] 65 2f [2] 63 1a [2] 4d 1a [2] 72 06 }

  condition:
    any of them
}