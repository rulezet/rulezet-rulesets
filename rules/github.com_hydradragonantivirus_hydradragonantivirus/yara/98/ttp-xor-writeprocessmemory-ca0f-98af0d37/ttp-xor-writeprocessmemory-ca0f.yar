rule TTP_XOR_WriteProcessMemory_ca0f {
  strings:
    $key_ca0f = { 9d 7d [2] af 5f [2] a9 6a [2] 87 6a [2] b8 76 }

  condition:
    any of them
}