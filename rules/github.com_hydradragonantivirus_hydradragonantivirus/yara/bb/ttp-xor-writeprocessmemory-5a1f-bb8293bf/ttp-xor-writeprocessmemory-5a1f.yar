rule TTP_XOR_WriteProcessMemory_5a1f {
  strings:
    $key_5a1f = { 0d 6d [2] 3f 4f [2] 39 7a [2] 17 7a [2] 28 66 }

  condition:
    any of them
}