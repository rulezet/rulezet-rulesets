rule TTP_XOR_WriteProcessMemory_1dff {
  strings:
    $key_1dff = { 4a 8d [2] 78 af [2] 7e 9a [2] 50 9a [2] 6f 86 }

  condition:
    any of them
}