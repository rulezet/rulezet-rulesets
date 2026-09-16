rule TTP_XOR_WriteProcessMemory_b23f {
  strings:
    $key_b23f = { e5 4d [2] d7 6f [2] d1 5a [2] ff 5a [2] c0 46 }

  condition:
    any of them
}