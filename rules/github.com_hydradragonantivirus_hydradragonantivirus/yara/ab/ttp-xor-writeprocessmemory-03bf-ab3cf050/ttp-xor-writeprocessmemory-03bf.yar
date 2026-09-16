rule TTP_XOR_WriteProcessMemory_03bf {
  strings:
    $key_03bf = { 54 cd [2] 66 ef [2] 60 da [2] 4e da [2] 71 c6 }

  condition:
    any of them
}