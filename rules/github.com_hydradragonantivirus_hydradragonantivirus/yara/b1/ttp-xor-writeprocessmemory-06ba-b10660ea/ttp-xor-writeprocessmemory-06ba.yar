rule TTP_XOR_WriteProcessMemory_06ba {
  strings:
    $key_06ba = { 51 c8 [2] 63 ea [2] 65 df [2] 4b df [2] 74 c3 }

  condition:
    any of them
}