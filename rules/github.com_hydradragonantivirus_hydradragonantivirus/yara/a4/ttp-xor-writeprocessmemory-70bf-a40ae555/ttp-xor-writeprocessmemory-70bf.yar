rule TTP_XOR_WriteProcessMemory_70bf {
  strings:
    $key_70bf = { 27 cd [2] 15 ef [2] 13 da [2] 3d da [2] 02 c6 }

  condition:
    any of them
}