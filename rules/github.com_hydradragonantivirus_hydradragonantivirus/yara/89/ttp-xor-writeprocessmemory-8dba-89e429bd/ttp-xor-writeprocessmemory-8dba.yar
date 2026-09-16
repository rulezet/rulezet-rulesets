rule TTP_XOR_WriteProcessMemory_8dba {
  strings:
    $key_8dba = { da c8 [2] e8 ea [2] ee df [2] c0 df [2] ff c3 }

  condition:
    any of them
}