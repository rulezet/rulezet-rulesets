rule TTP_XOR_WriteProcessMemory_e42a {
  strings:
    $key_e42a = { b3 58 [2] 81 7a [2] 87 4f [2] a9 4f [2] 96 53 }

  condition:
    any of them
}