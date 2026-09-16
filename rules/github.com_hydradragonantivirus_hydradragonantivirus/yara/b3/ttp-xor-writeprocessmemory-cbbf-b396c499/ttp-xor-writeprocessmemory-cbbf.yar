rule TTP_XOR_WriteProcessMemory_cbbf {
  strings:
    $key_cbbf = { 9c cd [2] ae ef [2] a8 da [2] 86 da [2] b9 c6 }

  condition:
    any of them
}