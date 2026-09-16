rule TTP_XOR_WriteProcessMemory_19ba {
  strings:
    $key_19ba = { 4e c8 [2] 7c ea [2] 7a df [2] 54 df [2] 6b c3 }

  condition:
    any of them
}