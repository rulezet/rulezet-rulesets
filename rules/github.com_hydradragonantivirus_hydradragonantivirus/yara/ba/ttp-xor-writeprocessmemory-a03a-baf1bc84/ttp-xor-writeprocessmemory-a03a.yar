rule TTP_XOR_WriteProcessMemory_a03a {
  strings:
    $key_a03a = { f7 48 [2] c5 6a [2] c3 5f [2] ed 5f [2] d2 43 }

  condition:
    any of them
}