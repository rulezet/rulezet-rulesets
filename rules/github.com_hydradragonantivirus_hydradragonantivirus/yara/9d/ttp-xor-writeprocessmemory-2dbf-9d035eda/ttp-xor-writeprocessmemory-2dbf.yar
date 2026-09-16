rule TTP_XOR_WriteProcessMemory_2dbf {
  strings:
    $key_2dbf = { 7a cd [2] 48 ef [2] 4e da [2] 60 da [2] 5f c6 }

  condition:
    any of them
}