rule TTP_XOR_WriteProcessMemory_322f {
  strings:
    $key_322f = { 65 5d [2] 57 7f [2] 51 4a [2] 7f 4a [2] 40 56 }

  condition:
    any of them
}