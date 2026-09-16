rule TTP_XOR_WriteProcessMemory_7df4 {
  strings:
    $key_7df4 = { 2a 86 [2] 18 a4 [2] 1e 91 [2] 30 91 [2] 0f 8d }

  condition:
    any of them
}