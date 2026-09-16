rule TTP_XOR_WriteProcessMemory_d05d {
  strings:
    $key_d05d = { 87 2f [2] b5 0d [2] b3 38 [2] 9d 38 [2] a2 24 }

  condition:
    any of them
}