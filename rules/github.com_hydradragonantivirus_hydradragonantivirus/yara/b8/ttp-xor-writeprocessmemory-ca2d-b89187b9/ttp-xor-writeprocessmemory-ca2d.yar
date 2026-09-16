rule TTP_XOR_WriteProcessMemory_ca2d {
  strings:
    $key_ca2d = { 9d 5f [2] af 7d [2] a9 48 [2] 87 48 [2] b8 54 }

  condition:
    any of them
}