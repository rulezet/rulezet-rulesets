rule TTP_XOR_WriteProcessMemory_1dbf {
  strings:
    $key_1dbf = { 4a cd [2] 78 ef [2] 7e da [2] 50 da [2] 6f c6 }

  condition:
    any of them
}