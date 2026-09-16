rule TTP_XOR_WriteProcessMemory_8edc {
  strings:
    $key_8edc = { d9 ae [2] eb 8c [2] ed b9 [2] c3 b9 [2] fc a5 }

  condition:
    any of them
}