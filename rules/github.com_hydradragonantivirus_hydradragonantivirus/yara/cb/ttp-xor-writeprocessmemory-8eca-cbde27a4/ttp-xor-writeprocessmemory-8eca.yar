rule TTP_XOR_WriteProcessMemory_8eca {
  strings:
    $key_8eca = { d9 b8 [2] eb 9a [2] ed af [2] c3 af [2] fc b3 }

  condition:
    any of them
}