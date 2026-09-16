rule TTP_XOR_WriteProcessMemory_dabf {
  strings:
    $key_dabf = { 8d cd [2] bf ef [2] b9 da [2] 97 da [2] a8 c6 }

  condition:
    any of them
}