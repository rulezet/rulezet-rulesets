rule TTP_XOR_WriteProcessMemory_170f {
  strings:
    $key_170f = { 40 7d [2] 72 5f [2] 74 6a [2] 5a 6a [2] 65 76 }

  condition:
    any of them
}