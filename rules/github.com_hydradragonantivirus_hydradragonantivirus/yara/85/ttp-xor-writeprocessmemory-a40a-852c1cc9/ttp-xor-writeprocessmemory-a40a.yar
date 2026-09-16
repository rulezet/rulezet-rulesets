rule TTP_XOR_WriteProcessMemory_a40a {
  strings:
    $key_a40a = { f3 78 [2] c1 5a [2] c7 6f [2] e9 6f [2] d6 73 }

  condition:
    any of them
}