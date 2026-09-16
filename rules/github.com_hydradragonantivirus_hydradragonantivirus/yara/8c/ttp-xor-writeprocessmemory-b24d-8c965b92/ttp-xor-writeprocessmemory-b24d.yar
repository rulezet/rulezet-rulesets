rule TTP_XOR_WriteProcessMemory_b24d {
  strings:
    $key_b24d = { e5 3f [2] d7 1d [2] d1 28 [2] ff 28 [2] c0 34 }

  condition:
    any of them
}