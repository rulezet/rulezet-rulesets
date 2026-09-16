rule TTP_XOR_WriteProcessMemory_55ba {
  strings:
    $key_55ba = { 02 c8 [2] 30 ea [2] 36 df [2] 18 df [2] 27 c3 }

  condition:
    any of them
}