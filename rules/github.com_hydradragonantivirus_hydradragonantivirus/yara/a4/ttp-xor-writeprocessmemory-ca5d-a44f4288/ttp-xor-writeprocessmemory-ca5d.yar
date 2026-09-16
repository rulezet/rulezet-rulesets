rule TTP_XOR_WriteProcessMemory_ca5d {
  strings:
    $key_ca5d = { 9d 2f [2] af 0d [2] a9 38 [2] 87 38 [2] b8 24 }

  condition:
    any of them
}