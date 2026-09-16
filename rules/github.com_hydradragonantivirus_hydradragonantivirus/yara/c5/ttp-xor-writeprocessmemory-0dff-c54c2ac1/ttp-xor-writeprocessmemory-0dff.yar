rule TTP_XOR_WriteProcessMemory_0dff {
  strings:
    $key_0dff = { 5a 8d [2] 68 af [2] 6e 9a [2] 40 9a [2] 7f 86 }

  condition:
    any of them
}