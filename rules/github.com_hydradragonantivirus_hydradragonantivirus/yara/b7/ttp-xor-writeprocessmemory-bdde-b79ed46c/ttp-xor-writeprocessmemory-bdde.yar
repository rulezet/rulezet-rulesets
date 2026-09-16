rule TTP_XOR_WriteProcessMemory_bdde {
  strings:
    $key_bdde = { ea ac [2] d8 8e [2] de bb [2] f0 bb [2] cf a7 }

  condition:
    any of them
}