rule TTP_XOR_WriteProcessMemory_8ecb {
  strings:
    $key_8ecb = { d9 b9 [2] eb 9b [2] ed ae [2] c3 ae [2] fc b2 }

  condition:
    any of them
}