rule TTP_XOR_WriteProcessMemory_e67f {
  strings:
    $key_e67f = { b1 0d [2] 83 2f [2] 85 1a [2] ab 1a [2] 94 06 }

  condition:
    any of them
}