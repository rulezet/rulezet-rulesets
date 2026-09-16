rule TTP_XOR_WriteProcessMemory_42bf {
  strings:
    $key_42bf = { 15 cd [2] 27 ef [2] 21 da [2] 0f da [2] 30 c6 }

  condition:
    any of them
}