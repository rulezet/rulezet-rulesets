rule TTP_XOR_WriteProcessMemory_a13a {
  strings:
    $key_a13a = { f6 48 [2] c4 6a [2] c2 5f [2] ec 5f [2] d3 43 }

  condition:
    any of them
}