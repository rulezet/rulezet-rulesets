rule TTP_XOR_WriteProcessMemory_e47a {
  strings:
    $key_e47a = { b3 08 [2] 81 2a [2] 87 1f [2] a9 1f [2] 96 03 }

  condition:
    any of them
}