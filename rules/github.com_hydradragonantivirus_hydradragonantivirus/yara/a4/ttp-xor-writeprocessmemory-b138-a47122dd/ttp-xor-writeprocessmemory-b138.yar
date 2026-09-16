rule TTP_XOR_WriteProcessMemory_b138 {
  strings:
    $key_b138 = { e6 4a [2] d4 68 [2] d2 5d [2] fc 5d [2] c3 41 }

  condition:
    any of them
}