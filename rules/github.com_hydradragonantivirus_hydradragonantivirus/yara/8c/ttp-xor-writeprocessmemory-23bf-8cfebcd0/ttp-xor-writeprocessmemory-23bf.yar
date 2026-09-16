rule TTP_XOR_WriteProcessMemory_23bf {
  strings:
    $key_23bf = { 74 cd [2] 46 ef [2] 40 da [2] 6e da [2] 51 c6 }

  condition:
    any of them
}