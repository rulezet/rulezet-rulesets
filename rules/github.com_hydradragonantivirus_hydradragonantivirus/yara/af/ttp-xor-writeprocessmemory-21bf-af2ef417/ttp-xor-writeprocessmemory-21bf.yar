rule TTP_XOR_WriteProcessMemory_21bf {
  strings:
    $key_21bf = { 76 cd [2] 44 ef [2] 42 da [2] 6c da [2] 53 c6 }

  condition:
    any of them
}