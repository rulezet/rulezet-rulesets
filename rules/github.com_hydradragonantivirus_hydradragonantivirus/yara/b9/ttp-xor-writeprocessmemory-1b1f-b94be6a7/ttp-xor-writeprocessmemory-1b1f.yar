rule TTP_XOR_WriteProcessMemory_1b1f {
  strings:
    $key_1b1f = { 4c 6d [2] 7e 4f [2] 78 7a [2] 56 7a [2] 69 66 }

  condition:
    any of them
}