rule TTP_XOR_WriteProcessMemory_7f1f {
  strings:
    $key_7f1f = { 28 6d [2] 1a 4f [2] 1c 7a [2] 32 7a [2] 0d 66 }

  condition:
    any of them
}