rule TTP_XOR_WriteProcessMemory_0abf {
  strings:
    $key_0abf = { 5d cd [2] 6f ef [2] 69 da [2] 47 da [2] 78 c6 }

  condition:
    any of them
}