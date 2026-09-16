rule TTP_XOR_WriteProcessMemory_a20a {
  strings:
    $key_a20a = { f5 78 [2] c7 5a [2] c1 6f [2] ef 6f [2] d0 73 }

  condition:
    any of them
}