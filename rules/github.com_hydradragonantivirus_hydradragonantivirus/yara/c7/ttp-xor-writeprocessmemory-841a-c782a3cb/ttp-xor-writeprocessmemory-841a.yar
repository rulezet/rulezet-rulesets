rule TTP_XOR_WriteProcessMemory_841a {
  strings:
    $key_841a = { d3 68 [2] e1 4a [2] e7 7f [2] c9 7f [2] f6 63 }

  condition:
    any of them
}