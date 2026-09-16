rule TTP_XOR_WriteProcessMemory_b06a {
  strings:
    $key_b06a = { e7 18 [2] d5 3a [2] d3 0f [2] fd 0f [2] c2 13 }

  condition:
    any of them
}