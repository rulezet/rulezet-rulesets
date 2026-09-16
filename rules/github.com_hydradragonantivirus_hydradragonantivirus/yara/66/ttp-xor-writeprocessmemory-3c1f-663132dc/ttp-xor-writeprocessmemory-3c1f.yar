rule TTP_XOR_WriteProcessMemory_3c1f {
  strings:
    $key_3c1f = { 6b 6d [2] 59 4f [2] 5f 7a [2] 71 7a [2] 4e 66 }

  condition:
    any of them
}