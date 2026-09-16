rule TTP_XOR_WriteProcessMemory_b249 {
  strings:
    $key_b249 = { e5 3b [2] d7 19 [2] d1 2c [2] ff 2c [2] c0 30 }

  condition:
    any of them
}