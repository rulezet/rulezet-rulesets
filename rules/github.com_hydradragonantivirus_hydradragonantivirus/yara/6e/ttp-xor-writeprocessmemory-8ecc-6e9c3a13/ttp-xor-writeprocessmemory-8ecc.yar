rule TTP_XOR_WriteProcessMemory_8ecc {
  strings:
    $key_8ecc = { d9 be [2] eb 9c [2] ed a9 [2] c3 a9 [2] fc b5 }

  condition:
    any of them
}