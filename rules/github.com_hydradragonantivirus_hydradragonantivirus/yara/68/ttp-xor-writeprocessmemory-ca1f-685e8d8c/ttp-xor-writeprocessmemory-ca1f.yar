rule TTP_XOR_WriteProcessMemory_ca1f {
  strings:
    $key_ca1f = { 9d 6d [2] af 4f [2] a9 7a [2] 87 7a [2] b8 66 }

  condition:
    any of them
}