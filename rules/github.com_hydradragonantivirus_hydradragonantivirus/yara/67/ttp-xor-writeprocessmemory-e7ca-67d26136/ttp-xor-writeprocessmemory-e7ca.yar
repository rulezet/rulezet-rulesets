rule TTP_XOR_WriteProcessMemory_e7ca {
  strings:
    $key_e7ca = { b0 b8 [2] 82 9a [2] 84 af [2] aa af [2] 95 b3 }

  condition:
    any of them
}