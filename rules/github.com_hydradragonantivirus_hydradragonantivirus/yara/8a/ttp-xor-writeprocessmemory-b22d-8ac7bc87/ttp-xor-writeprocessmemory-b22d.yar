rule TTP_XOR_WriteProcessMemory_b22d {
  strings:
    $key_b22d = { e5 5f [2] d7 7d [2] d1 48 [2] ff 48 [2] c0 54 }

  condition:
    any of them
}