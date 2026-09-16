rule TTP_XOR_WriteProcessMemory_d51d {
  strings:
    $key_d51d = { 82 6f [2] b0 4d [2] b6 78 [2] 98 78 [2] a7 64 }

  condition:
    any of them
}