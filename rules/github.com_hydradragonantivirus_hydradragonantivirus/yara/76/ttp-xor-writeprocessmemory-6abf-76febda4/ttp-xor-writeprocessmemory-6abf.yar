rule TTP_XOR_WriteProcessMemory_6abf {
  strings:
    $key_6abf = { 3d cd [2] 0f ef [2] 09 da [2] 27 da [2] 18 c6 }

  condition:
    any of them
}