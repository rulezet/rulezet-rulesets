rule TTP_XOR_WriteProcessMemory_2abf {
  strings:
    $key_2abf = { 7d cd [2] 4f ef [2] 49 da [2] 67 da [2] 58 c6 }

  condition:
    any of them
}