rule TTP_XOR_WriteProcessMemory_24bf {
  strings:
    $key_24bf = { 73 cd [2] 41 ef [2] 47 da [2] 69 da [2] 56 c6 }

  condition:
    any of them
}