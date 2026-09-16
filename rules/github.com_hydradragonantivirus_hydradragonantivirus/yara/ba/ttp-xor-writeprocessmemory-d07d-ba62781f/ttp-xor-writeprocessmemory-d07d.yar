rule TTP_XOR_WriteProcessMemory_d07d {
  strings:
    $key_d07d = { 87 0f [2] b5 2d [2] b3 18 [2] 9d 18 [2] a2 04 }

  condition:
    any of them
}