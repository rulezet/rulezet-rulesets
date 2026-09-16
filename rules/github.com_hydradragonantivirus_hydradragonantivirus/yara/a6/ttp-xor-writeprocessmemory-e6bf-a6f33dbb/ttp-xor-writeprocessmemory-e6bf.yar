rule TTP_XOR_WriteProcessMemory_e6bf {
  strings:
    $key_e6bf = { b1 cd [2] 83 ef [2] 85 da [2] ab da [2] 94 c6 }

  condition:
    any of them
}