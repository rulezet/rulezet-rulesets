rule TTP_XOR_WriteProcessMemory_d01d {
  strings:
    $key_d01d = { 87 6f [2] b5 4d [2] b3 78 [2] 9d 78 [2] a2 64 }

  condition:
    any of them
}