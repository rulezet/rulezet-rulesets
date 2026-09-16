rule TTP_XOR_WriteProcessMemory_1cbf {
  strings:
    $key_1cbf = { 4b cd [2] 79 ef [2] 7f da [2] 51 da [2] 6e c6 }

  condition:
    any of them
}