rule TTP_XOR_WriteProcessMemory_27ba {
  strings:
    $key_27ba = { 70 c8 [2] 42 ea [2] 44 df [2] 6a df [2] 55 c3 }

  condition:
    any of them
}