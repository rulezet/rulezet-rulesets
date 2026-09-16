rule TTP_XOR_WriteProcessMemory_5abf {
  strings:
    $key_5abf = { 0d cd [2] 3f ef [2] 39 da [2] 17 da [2] 28 c6 }

  condition:
    any of them
}