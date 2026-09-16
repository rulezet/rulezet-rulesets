rule TTP_XOR_WriteProcessMemory_6dba {
  strings:
    $key_6dba = { 3a c8 [2] 08 ea [2] 0e df [2] 20 df [2] 1f c3 }

  condition:
    any of them
}