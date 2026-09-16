rule TTP_XOR_WriteProcessMemory_ca7d {
  strings:
    $key_ca7d = { 9d 0f [2] af 2d [2] a9 18 [2] 87 18 [2] b8 04 }

  condition:
    any of them
}