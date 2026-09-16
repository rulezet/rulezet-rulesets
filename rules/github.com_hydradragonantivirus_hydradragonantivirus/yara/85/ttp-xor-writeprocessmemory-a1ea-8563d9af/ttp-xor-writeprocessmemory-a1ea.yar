rule TTP_XOR_WriteProcessMemory_a1ea {
  strings:
    $key_a1ea = { f6 98 [2] c4 ba [2] c2 8f [2] ec 8f [2] d3 93 }

  condition:
    any of them
}