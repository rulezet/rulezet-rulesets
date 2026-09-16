rule TTP_XOR_WriteProcessMemory_0d2f {
  strings:
    $key_0d2f = { 5a 5d [2] 68 7f [2] 6e 4a [2] 40 4a [2] 7f 56 }

  condition:
    any of them
}