rule TTP_XOR_WriteProcessMemory_3c2f {
  strings:
    $key_3c2f = { 6b 5d [2] 59 7f [2] 5f 4a [2] 71 4a [2] 4e 56 }

  condition:
    any of them
}