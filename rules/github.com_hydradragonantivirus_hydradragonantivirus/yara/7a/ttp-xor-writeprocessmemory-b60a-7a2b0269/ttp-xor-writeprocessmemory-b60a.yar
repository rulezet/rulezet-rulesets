rule TTP_XOR_WriteProcessMemory_b60a {
  strings:
    $key_b60a = { e1 78 [2] d3 5a [2] d5 6f [2] fb 6f [2] c4 73 }

  condition:
    any of them
}