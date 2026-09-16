rule TTP_XOR_WriteProcessMemory_b269 {
  strings:
    $key_b269 = { e5 1b [2] d7 39 [2] d1 0c [2] ff 0c [2] c0 10 }

  condition:
    any of them
}