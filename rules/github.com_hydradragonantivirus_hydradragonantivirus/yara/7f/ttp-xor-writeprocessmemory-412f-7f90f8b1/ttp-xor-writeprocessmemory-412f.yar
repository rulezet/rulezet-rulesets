rule TTP_XOR_WriteProcessMemory_412f {
  strings:
    $key_412f = { 16 5d [2] 24 7f [2] 22 4a [2] 0c 4a [2] 33 56 }

  condition:
    any of them
}