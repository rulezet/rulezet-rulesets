rule TTP_XOR_WriteProcessMemory_b23a {
  strings:
    $key_b23a = { e5 48 [2] d7 6a [2] d1 5f [2] ff 5f [2] c0 43 }

  condition:
    any of them
}