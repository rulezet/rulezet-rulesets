rule TTP_XOR_WriteProcessMemory_bddc {
  strings:
    $key_bddc = { ea ae [2] d8 8c [2] de b9 [2] f0 b9 [2] cf a5 }

  condition:
    any of them
}