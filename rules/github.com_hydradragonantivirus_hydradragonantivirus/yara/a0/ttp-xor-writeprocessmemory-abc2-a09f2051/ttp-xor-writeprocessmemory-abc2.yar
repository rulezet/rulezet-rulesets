rule TTP_XOR_WriteProcessMemory_abc2 {
  strings:
    $key_abc2 = { fc b0 [2] ce 92 [2] c8 a7 [2] e6 a7 [2] d9 bb }

  condition:
    any of them
}