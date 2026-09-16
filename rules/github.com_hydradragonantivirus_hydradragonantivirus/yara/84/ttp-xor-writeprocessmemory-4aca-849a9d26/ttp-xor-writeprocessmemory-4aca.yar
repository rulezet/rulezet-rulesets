rule TTP_XOR_WriteProcessMemory_4aca {
  strings:
    $key_4aca = { 1d b8 [2] 2f 9a [2] 29 af [2] 07 af [2] 38 b3 }

  condition:
    any of them
}