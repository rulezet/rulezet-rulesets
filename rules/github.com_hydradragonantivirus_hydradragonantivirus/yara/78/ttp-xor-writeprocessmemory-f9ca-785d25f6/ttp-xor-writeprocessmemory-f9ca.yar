rule TTP_XOR_WriteProcessMemory_f9ca {
  strings:
    $key_f9ca = { ae b8 [2] 9c 9a [2] 9a af [2] b4 af [2] 8b b3 }

  condition:
    any of them
}