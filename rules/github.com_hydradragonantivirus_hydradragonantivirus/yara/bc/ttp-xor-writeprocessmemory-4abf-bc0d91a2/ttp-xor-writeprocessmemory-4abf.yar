rule TTP_XOR_WriteProcessMemory_4abf {
  strings:
    $key_4abf = { 1d cd [2] 2f ef [2] 29 da [2] 07 da [2] 38 c6 }

  condition:
    any of them
}