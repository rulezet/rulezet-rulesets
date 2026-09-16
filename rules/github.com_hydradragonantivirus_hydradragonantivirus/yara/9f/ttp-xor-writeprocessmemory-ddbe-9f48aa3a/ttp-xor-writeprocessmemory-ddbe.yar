rule TTP_XOR_WriteProcessMemory_ddbe {
  strings:
    $key_ddbe = { 8a cc [2] b8 ee [2] be db [2] 90 db [2] af c7 }

  condition:
    any of them
}