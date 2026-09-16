rule TTP_XOR_WriteProcessMemory_152f {
  strings:
    $key_152f = { 42 5d [2] 70 7f [2] 76 4a [2] 58 4a [2] 67 56 }

  condition:
    any of them
}