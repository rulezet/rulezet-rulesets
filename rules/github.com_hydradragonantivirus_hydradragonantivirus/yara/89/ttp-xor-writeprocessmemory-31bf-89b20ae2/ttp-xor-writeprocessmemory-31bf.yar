rule TTP_XOR_WriteProcessMemory_31bf {
  strings:
    $key_31bf = { 66 cd [2] 54 ef [2] 52 da [2] 7c da [2] 43 c6 }

  condition:
    any of them
}