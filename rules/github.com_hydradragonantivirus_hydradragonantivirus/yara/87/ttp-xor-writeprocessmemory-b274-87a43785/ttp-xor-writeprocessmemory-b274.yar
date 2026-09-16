rule TTP_XOR_WriteProcessMemory_b274 {
  strings:
    $key_b274 = { e5 06 [2] d7 24 [2] d1 11 [2] ff 11 [2] c0 0d }

  condition:
    any of them
}