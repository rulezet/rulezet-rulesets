rule TTP_XOR_WriteProcessMemory_0a1f {
  strings:
    $key_0a1f = { 5d 6d [2] 6f 4f [2] 69 7a [2] 47 7a [2] 78 66 }

  condition:
    any of them
}