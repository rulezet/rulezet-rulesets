rule TTP_XOR_WriteProcessMemory_e46a {
  strings:
    $key_e46a = { b3 18 [2] 81 3a [2] 87 0f [2] a9 0f [2] 96 13 }

  condition:
    any of them
}