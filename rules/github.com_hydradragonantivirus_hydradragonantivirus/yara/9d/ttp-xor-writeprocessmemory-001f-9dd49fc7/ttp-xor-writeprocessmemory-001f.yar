rule TTP_XOR_WriteProcessMemory_001f {
  strings:
    $key_001f = { 57 6d [2] 65 4f [2] 63 7a [2] 4d 7a [2] 72 66 }

  condition:
    any of them
}