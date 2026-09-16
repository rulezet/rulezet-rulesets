rule TTP_XOR_WriteProcessMemory_e03f {
  strings:
    $key_e03f = { b7 4d [2] 85 6f [2] 83 5a [2] ad 5a [2] 92 46 }

  condition:
    any of them
}