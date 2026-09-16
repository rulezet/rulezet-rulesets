rule TTP_XOR_WriteProcessMemory_b186 {
  strings:
    $key_b186 = { e6 f4 [2] d4 d6 [2] d2 e3 [2] fc e3 [2] c3 ff }

  condition:
    any of them
}