rule TTP_XOR_WriteProcessMemory_b618 {
  strings:
    $key_b618 = { e1 6a [2] d3 48 [2] d5 7d [2] fb 7d [2] c4 61 }

  condition:
    any of them
}