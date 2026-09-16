rule TTP_XOR_WriteProcessMemory_0bbf {
  strings:
    $key_0bbf = { 5c cd [2] 6e ef [2] 68 da [2] 46 da [2] 79 c6 }

  condition:
    any of them
}