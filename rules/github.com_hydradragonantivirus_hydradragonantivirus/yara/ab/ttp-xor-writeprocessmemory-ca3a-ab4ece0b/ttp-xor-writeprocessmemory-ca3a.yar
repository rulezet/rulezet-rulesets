rule TTP_XOR_WriteProcessMemory_ca3a {
  strings:
    $key_ca3a = { 9d 48 [2] af 6a [2] a9 5f [2] 87 5f [2] b8 43 }

  condition:
    any of them
}