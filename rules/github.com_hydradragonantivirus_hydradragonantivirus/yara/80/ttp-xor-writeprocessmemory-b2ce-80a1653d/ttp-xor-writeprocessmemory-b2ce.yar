rule TTP_XOR_WriteProcessMemory_b2ce {
  strings:
    $key_b2ce = { e5 bc [2] d7 9e [2] d1 ab [2] ff ab [2] c0 b7 }

  condition:
    any of them
}