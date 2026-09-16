rule TTP_XOR_WriteProcessMemory_f8ca {
  strings:
    $key_f8ca = { af b8 [2] 9d 9a [2] 9b af [2] b5 af [2] 8a b3 }

  condition:
    any of them
}