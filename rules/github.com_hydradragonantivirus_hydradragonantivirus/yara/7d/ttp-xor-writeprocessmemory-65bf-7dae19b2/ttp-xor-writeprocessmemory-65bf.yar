rule TTP_XOR_WriteProcessMemory_65bf {
  strings:
    $key_65bf = { 32 cd [2] 00 ef [2] 06 da [2] 28 da [2] 17 c6 }

  condition:
    any of them
}