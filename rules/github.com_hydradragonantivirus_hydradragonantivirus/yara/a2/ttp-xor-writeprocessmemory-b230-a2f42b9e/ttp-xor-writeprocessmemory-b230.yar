rule TTP_XOR_WriteProcessMemory_b230 {
  strings:
    $key_b230 = { e5 42 [2] d7 60 [2] d1 55 [2] ff 55 [2] c0 49 }

  condition:
    any of them
}