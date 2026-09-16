rule TTP_XOR_WriteProcessMemory_000f {
  strings:
    $key_000f = { 57 7d [2] 65 5f [2] 63 6a [2] 4d 6a [2] 72 76 }

  condition:
    any of them
}