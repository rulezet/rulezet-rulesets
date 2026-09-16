rule TTP_XOR_WriteProcessMemory_02ba {
  strings:
    $key_02ba = { 55 c8 [2] 67 ea [2] 61 df [2] 4f df [2] 70 c3 }

  condition:
    any of them
}