rule TTP_XOR_WriteProcessMemory_c8ca {
  strings:
    $key_c8ca = { 9f b8 [2] ad 9a [2] ab af [2] 85 af [2] ba b3 }

  condition:
    any of them
}