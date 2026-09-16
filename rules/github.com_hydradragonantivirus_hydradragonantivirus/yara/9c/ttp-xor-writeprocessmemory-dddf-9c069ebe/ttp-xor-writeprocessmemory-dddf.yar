rule TTP_XOR_WriteProcessMemory_dddf {
  strings:
    $key_dddf = { 8a ad [2] b8 8f [2] be ba [2] 90 ba [2] af a6 }

  condition:
    any of them
}