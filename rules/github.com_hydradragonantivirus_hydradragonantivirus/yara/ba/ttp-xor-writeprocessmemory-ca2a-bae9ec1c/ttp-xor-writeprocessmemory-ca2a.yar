rule TTP_XOR_WriteProcessMemory_ca2a {
  strings:
    $key_ca2a = { 9d 58 [2] af 7a [2] a9 4f [2] 87 4f [2] b8 53 }

  condition:
    any of them
}