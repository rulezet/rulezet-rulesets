rule TTP_XOR_WriteProcessMemory_4cbf {
  strings:
    $key_4cbf = { 1b cd [2] 29 ef [2] 2f da [2] 01 da [2] 3e c6 }

  condition:
    any of them
}