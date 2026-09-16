rule TTP_XOR_WriteProcessMemory_e43f {
  strings:
    $key_e43f = { b3 4d [2] 81 6f [2] 87 5a [2] a9 5a [2] 96 46 }

  condition:
    any of them
}