rule TTP_XOR_WriteProcessMemory_dda5 {
  strings:
    $key_dda5 = { 8a d7 [2] b8 f5 [2] be c0 [2] 90 c0 [2] af dc }

  condition:
    any of them
}