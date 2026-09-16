rule TTP_XOR_WriteProcessMemory_ca3f {
  strings:
    $key_ca3f = { 9d 4d [2] af 6f [2] a9 5a [2] 87 5a [2] b8 46 }

  condition:
    any of them
}