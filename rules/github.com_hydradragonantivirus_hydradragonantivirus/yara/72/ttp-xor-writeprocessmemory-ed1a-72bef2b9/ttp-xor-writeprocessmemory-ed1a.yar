rule TTP_XOR_WriteProcessMemory_ed1a {
  strings:
    $key_ed1a = { ba 68 [2] 88 4a [2] 8e 7f [2] a0 7f [2] 9f 63 }

  condition:
    any of them
}