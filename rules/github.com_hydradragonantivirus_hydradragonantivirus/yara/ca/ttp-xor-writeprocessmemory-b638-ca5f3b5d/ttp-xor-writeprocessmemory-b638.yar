rule TTP_XOR_WriteProcessMemory_b638 {
  strings:
    $key_b638 = { e1 4a [2] d3 68 [2] d5 5d [2] fb 5d [2] c4 41 }

  condition:
    any of them
}