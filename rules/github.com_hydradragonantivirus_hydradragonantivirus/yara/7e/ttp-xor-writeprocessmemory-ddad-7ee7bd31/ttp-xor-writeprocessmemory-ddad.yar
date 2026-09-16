rule TTP_XOR_WriteProcessMemory_ddad {
  strings:
    $key_ddad = { 8a df [2] b8 fd [2] be c8 [2] 90 c8 [2] af d4 }

  condition:
    any of them
}