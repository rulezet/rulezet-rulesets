rule TTP_XOR_WriteProcessMemory_e01f {
  strings:
    $key_e01f = { b7 6d [2] 85 4f [2] 83 7a [2] ad 7a [2] 92 66 }

  condition:
    any of them
}