rule TTP_XOR_WriteProcessMemory_a00a {
  strings:
    $key_a00a = { f7 78 [2] c5 5a [2] c3 6f [2] ed 6f [2] d2 73 }

  condition:
    any of them
}