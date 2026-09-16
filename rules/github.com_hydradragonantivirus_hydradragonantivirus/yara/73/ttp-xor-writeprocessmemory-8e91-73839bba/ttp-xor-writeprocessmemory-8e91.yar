rule TTP_XOR_WriteProcessMemory_8e91 {
  strings:
    $key_8e91 = { d9 e3 [2] eb c1 [2] ed f4 [2] c3 f4 [2] fc e8 }

  condition:
    any of them
}