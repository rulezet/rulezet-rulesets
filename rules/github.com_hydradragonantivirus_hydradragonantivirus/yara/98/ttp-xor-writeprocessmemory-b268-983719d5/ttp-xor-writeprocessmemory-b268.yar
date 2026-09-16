rule TTP_XOR_WriteProcessMemory_b268 {
  strings:
    $key_b268 = { e5 1a [2] d7 38 [2] d1 0d [2] ff 0d [2] c0 11 }

  condition:
    any of them
}