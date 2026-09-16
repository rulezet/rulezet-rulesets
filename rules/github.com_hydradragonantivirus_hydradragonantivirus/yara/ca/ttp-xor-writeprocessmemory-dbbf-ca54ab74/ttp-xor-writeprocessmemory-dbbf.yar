rule TTP_XOR_WriteProcessMemory_dbbf {
  strings:
    $key_dbbf = { 8c cd [2] be ef [2] b8 da [2] 96 da [2] a9 c6 }

  condition:
    any of them
}