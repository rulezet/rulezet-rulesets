rule TTP_XOR_WriteProcessMemory_8edd {
  strings:
    $key_8edd = { d9 af [2] eb 8d [2] ed b8 [2] c3 b8 [2] fc a4 }

  condition:
    any of them
}