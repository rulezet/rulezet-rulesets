rule TTP_XOR_WriteProcessMemory_5dbf {
  strings:
    $key_5dbf = { 0a cd [2] 38 ef [2] 3e da [2] 10 da [2] 2f c6 }

  condition:
    any of them
}