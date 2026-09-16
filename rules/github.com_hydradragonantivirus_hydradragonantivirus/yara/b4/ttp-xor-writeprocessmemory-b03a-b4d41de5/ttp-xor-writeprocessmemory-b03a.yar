rule TTP_XOR_WriteProcessMemory_b03a {
  strings:
    $key_b03a = { e7 48 [2] d5 6a [2] d3 5f [2] fd 5f [2] c2 43 }

  condition:
    any of them
}