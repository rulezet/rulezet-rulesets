rule TTP_XOR_WriteProcessMemory_8edb {
  strings:
    $key_8edb = { d9 a9 [2] eb 8b [2] ed be [2] c3 be [2] fc a2 }

  condition:
    any of them
}