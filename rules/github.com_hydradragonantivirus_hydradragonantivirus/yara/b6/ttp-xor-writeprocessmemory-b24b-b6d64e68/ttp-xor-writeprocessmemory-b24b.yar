rule TTP_XOR_WriteProcessMemory_b24b {
  strings:
    $key_b24b = { e5 39 [2] d7 1b [2] d1 2e [2] ff 2e [2] c0 32 }

  condition:
    any of them
}