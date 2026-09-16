rule TTP_XOR_WriteProcessMemory_61ca {
  strings:
    $key_61ca = { 36 b8 [2] 04 9a [2] 02 af [2] 2c af [2] 13 b3 }

  condition:
    any of them
}