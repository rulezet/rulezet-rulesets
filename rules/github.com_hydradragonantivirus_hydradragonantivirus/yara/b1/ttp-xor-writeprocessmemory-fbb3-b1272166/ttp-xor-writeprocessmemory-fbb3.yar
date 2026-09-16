rule TTP_XOR_WriteProcessMemory_fbb3 {
  strings:
    $key_fbb3 = { ac c1 [2] 9e e3 [2] 98 d6 [2] b6 d6 [2] 89 ca }

  condition:
    any of them
}