rule TTP_XOR_WriteProcessMemory_b019 {
  strings:
    $key_b019 = { e7 6b [2] d5 49 [2] d3 7c [2] fd 7c [2] c2 60 }

  condition:
    any of them
}