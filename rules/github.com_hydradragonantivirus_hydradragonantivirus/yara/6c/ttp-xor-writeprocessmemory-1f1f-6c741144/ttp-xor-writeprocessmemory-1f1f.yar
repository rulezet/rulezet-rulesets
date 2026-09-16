rule TTP_XOR_WriteProcessMemory_1f1f {
  strings:
    $key_1f1f = { 48 6d [2] 7a 4f [2] 7c 7a [2] 52 7a [2] 6d 66 }

  condition:
    any of them
}