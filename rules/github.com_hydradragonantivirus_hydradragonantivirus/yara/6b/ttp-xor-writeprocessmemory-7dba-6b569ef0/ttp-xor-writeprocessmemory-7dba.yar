rule TTP_XOR_WriteProcessMemory_7dba {
  strings:
    $key_7dba = { 2a c8 [2] 18 ea [2] 1e df [2] 30 df [2] 0f c3 }

  condition:
    any of them
}