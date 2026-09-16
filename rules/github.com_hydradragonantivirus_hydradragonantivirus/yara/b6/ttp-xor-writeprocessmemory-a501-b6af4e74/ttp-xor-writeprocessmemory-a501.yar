rule TTP_XOR_WriteProcessMemory_a501 {
  strings:
    $key_a501 = { f2 73 [2] c0 51 [2] c6 64 [2] e8 64 [2] d7 78 }

  condition:
    any of them
}