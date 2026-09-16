rule TTP_XOR_WriteProcessMemory_e45a {
  strings:
    $key_e45a = { b3 28 [2] 81 0a [2] 87 3f [2] a9 3f [2] 96 23 }

  condition:
    any of them
}