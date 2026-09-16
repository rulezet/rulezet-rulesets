rule TTP_XOR_WriteProcessMemory_5a2f {
  strings:
    $key_5a2f = { 0d 5d [2] 3f 7f [2] 39 4a [2] 17 4a [2] 28 56 }

  condition:
    any of them
}