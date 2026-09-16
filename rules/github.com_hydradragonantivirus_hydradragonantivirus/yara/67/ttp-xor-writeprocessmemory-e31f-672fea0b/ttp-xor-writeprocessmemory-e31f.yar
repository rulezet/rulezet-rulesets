rule TTP_XOR_WriteProcessMemory_e31f {
  strings:
    $key_e31f = { b4 6d [2] 86 4f [2] 80 7a [2] ae 7a [2] 91 66 }

  condition:
    any of them
}