rule TTP_XOR_WriteProcessMemory_a996 {
  strings:
    $key_a996 = { fe e4 [2] cc c6 [2] ca f3 [2] e4 f3 [2] db ef }

  condition:
    any of them
}