rule TTP_XOR_WriteProcessMemory_ed2a {
  strings:
    $key_ed2a = { ba 58 [2] 88 7a [2] 8e 4f [2] a0 4f [2] 9f 53 }

  condition:
    any of them
}