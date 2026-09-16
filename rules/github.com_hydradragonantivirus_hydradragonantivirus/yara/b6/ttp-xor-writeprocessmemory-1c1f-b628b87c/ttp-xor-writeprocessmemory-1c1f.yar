rule TTP_XOR_WriteProcessMemory_1c1f {
  strings:
    $key_1c1f = { 4b 6d [2] 79 4f [2] 7f 7a [2] 51 7a [2] 6e 66 }

  condition:
    any of them
}