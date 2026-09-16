rule TTP_XOR_WriteProcessMemory_bda7 {
  strings:
    $key_bda7 = { ea d5 [2] d8 f7 [2] de c2 [2] f0 c2 [2] cf de }

  condition:
    any of them
}