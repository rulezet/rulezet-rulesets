rule TTP_XOR_WriteProcessMemory_d47a {
  strings:
    $key_d47a = { 83 08 [2] b1 2a [2] b7 1f [2] 99 1f [2] a6 03 }

  condition:
    any of them
}