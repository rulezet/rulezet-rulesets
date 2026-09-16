rule TTP_XOR_WriteProcessMemory_23ce {
  strings:
    $key_23ce = { 74 bc [2] 46 9e [2] 40 ab [2] 6e ab [2] 51 b7 }

  condition:
    any of them
}