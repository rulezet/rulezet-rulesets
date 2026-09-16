rule TTP_XOR_WriteProcessMemory_90bf {
  strings:
    $key_90bf = { c7 cd [2] f5 ef [2] f3 da [2] dd da [2] e2 c6 }

  condition:
    any of them
}