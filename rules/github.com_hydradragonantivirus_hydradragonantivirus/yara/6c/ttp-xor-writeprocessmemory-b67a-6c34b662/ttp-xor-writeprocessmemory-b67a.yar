rule TTP_XOR_WriteProcessMemory_b67a {
  strings:
    $key_b67a = { e1 08 [2] d3 2a [2] d5 1f [2] fb 1f [2] c4 03 }

  condition:
    any of them
}