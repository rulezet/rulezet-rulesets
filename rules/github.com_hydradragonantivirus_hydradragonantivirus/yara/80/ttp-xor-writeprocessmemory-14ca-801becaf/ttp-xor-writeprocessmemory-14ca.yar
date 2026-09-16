rule TTP_XOR_WriteProcessMemory_14ca {
  strings:
    $key_14ca = { 43 b8 [2] 71 9a [2] 77 af [2] 59 af [2] 66 b3 }

  condition:
    any of them
}