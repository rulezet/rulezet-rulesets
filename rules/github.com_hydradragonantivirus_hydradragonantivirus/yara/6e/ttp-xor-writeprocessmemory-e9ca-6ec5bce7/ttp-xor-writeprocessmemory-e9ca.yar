rule TTP_XOR_WriteProcessMemory_e9ca {
  strings:
    $key_e9ca = { be b8 [2] 8c 9a [2] 8a af [2] a4 af [2] 9b b3 }

  condition:
    any of them
}