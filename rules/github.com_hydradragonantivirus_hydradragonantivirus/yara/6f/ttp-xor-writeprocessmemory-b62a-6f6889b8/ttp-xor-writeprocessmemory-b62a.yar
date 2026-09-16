rule TTP_XOR_WriteProcessMemory_b62a {
  strings:
    $key_b62a = { e1 58 [2] d3 7a [2] d5 4f [2] fb 4f [2] c4 53 }

  condition:
    any of them
}