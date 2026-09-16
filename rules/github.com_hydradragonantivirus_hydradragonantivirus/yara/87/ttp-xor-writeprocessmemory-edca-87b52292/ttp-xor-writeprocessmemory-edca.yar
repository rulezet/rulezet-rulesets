rule TTP_XOR_WriteProcessMemory_edca {
  strings:
    $key_edca = { ba b8 [2] 88 9a [2] 8e af [2] a0 af [2] 9f b3 }

  condition:
    any of them
}