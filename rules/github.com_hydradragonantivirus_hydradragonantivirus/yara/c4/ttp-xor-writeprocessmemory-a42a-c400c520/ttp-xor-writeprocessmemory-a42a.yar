rule TTP_XOR_WriteProcessMemory_a42a {
  strings:
    $key_a42a = { f3 58 [2] c1 7a [2] c7 4f [2] e9 4f [2] d6 53 }

  condition:
    any of them
}