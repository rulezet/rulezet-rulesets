rule TTP_XOR_WriteProcessMemory_680f {
  strings:
    $key_680f = { 3f 7d [2] 0d 5f [2] 0b 6a [2] 25 6a [2] 1a 76 }

  condition:
    any of them
}