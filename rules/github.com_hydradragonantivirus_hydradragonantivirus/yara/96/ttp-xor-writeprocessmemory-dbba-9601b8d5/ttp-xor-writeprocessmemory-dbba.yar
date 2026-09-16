rule TTP_XOR_WriteProcessMemory_dbba {
  strings:
    $key_dbba = { 8c c8 [2] be ea [2] b8 df [2] 96 df [2] a9 c3 }

  condition:
    any of them
}