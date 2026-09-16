rule TTP_XOR_WriteProcessMemory_b259 {
  strings:
    $key_b259 = { e5 2b [2] d7 09 [2] d1 3c [2] ff 3c [2] c0 20 }

  condition:
    any of them
}