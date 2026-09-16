rule TTP_XOR_WriteProcessMemory_8e96 {
  strings:
    $key_8e96 = { d9 e4 [2] eb c6 [2] ed f3 [2] c3 f3 [2] fc ef }

  condition:
    any of them
}