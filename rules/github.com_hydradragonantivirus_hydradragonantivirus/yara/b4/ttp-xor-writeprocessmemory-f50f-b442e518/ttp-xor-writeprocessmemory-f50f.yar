rule TTP_XOR_WriteProcessMemory_f50f {
  strings:
    $key_f50f = { a2 7d [2] 90 5f [2] 96 6a [2] b8 6a [2] 87 76 }

  condition:
    any of them
}