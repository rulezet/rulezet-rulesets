rule TTP_XOR_WriteProcessMemory_74bf {
  strings:
    $key_74bf = { 23 cd [2] 11 ef [2] 17 da [2] 39 da [2] 06 c6 }

  condition:
    any of them
}