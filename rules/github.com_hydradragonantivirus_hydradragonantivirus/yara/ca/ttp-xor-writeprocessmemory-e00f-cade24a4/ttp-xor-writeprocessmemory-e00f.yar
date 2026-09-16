rule TTP_XOR_WriteProcessMemory_e00f {
  strings:
    $key_e00f = { b7 7d [2] 85 5f [2] 83 6a [2] ad 6a [2] 92 76 }

  condition:
    any of them
}