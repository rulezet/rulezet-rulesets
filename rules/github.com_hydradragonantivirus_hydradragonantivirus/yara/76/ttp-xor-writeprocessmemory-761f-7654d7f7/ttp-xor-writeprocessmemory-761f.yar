rule TTP_XOR_WriteProcessMemory_761f {
  strings:
    $key_761f = { 21 6d [2] 13 4f [2] 15 7a [2] 3b 7a [2] 04 66 }

  condition:
    any of them
}