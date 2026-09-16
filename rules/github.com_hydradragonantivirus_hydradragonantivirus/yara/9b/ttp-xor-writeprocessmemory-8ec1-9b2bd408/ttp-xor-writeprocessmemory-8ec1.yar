rule TTP_XOR_WriteProcessMemory_8ec1 {
  strings:
    $key_8ec1 = { d9 b3 [2] eb 91 [2] ed a4 [2] c3 a4 [2] fc b8 }

  condition:
    any of them
}