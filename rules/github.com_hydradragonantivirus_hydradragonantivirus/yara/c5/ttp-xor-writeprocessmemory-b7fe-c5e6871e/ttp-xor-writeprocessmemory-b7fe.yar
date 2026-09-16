rule TTP_XOR_WriteProcessMemory_b7fe {
  strings:
    $key_b7fe = { e0 8c [2] d2 ae [2] d4 9b [2] fa 9b [2] c5 87 }

  condition:
    any of them
}