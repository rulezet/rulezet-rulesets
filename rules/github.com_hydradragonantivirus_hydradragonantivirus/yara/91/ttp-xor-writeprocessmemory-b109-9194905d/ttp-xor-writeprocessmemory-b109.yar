rule TTP_XOR_WriteProcessMemory_b109 {
  strings:
    $key_b109 = { e6 7b [2] d4 59 [2] d2 6c [2] fc 6c [2] c3 70 }

  condition:
    any of them
}