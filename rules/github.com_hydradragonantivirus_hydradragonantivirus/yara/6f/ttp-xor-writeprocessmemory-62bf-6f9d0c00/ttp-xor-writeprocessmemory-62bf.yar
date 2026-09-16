rule TTP_XOR_WriteProcessMemory_62bf {
  strings:
    $key_62bf = { 35 cd [2] 07 ef [2] 01 da [2] 2f da [2] 10 c6 }

  condition:
    any of them
}