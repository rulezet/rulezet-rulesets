rule TTP_XOR_WriteProcessMemory_caca {
  strings:
    $key_caca = { 9d b8 [2] af 9a [2] a9 af [2] 87 af [2] b8 b3 }

  condition:
    any of them
}