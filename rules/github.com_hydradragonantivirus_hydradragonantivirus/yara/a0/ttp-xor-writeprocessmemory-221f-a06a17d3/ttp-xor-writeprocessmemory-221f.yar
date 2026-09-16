rule TTP_XOR_WriteProcessMemory_221f {
  strings:
    $key_221f = { 75 6d [2] 47 4f [2] 41 7a [2] 6f 7a [2] 50 66 }

  condition:
    any of them
}