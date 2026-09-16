rule TTP_XOR_WriteProcessMemory_cabf {
  strings:
    $key_cabf = { 9d cd [2] af ef [2] a9 da [2] 87 da [2] b8 c6 }

  condition:
    any of them
}