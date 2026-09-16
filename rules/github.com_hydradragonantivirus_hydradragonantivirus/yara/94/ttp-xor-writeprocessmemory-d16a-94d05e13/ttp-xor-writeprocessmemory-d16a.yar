rule TTP_XOR_WriteProcessMemory_d16a {
  strings:
    $key_d16a = { 86 18 [2] b4 3a [2] b2 0f [2] 9c 0f [2] a3 13 }

  condition:
    any of them
}