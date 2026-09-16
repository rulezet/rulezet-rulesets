rule TTP_XOR_WriteProcessMemory_bdac {
  strings:
    $key_bdac = { ea de [2] d8 fc [2] de c9 [2] f0 c9 [2] cf d5 }

  condition:
    any of them
}