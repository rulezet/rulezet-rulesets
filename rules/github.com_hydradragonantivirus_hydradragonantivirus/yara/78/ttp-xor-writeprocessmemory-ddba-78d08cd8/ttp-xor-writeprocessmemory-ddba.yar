rule TTP_XOR_WriteProcessMemory_ddba {
  strings:
    $key_ddba = { 8a c8 [2] b8 ea [2] be df [2] 90 df [2] af c3 }

  condition:
    any of them
}