rule TTP_XOR_WriteProcessMemory_e8ca {
  strings:
    $key_e8ca = { bf b8 [2] 8d 9a [2] 8b af [2] a5 af [2] 9a b3 }

  condition:
    any of them
}