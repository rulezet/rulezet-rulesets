rule TTP_XOR_WriteProcessMemory_a07a {
  strings:
    $key_a07a = { f7 08 [2] c5 2a [2] c3 1f [2] ed 1f [2] d2 03 }

  condition:
    any of them
}