rule TTP_XOR_WriteProcessMemory_d11a {
  strings:
    $key_d11a = { 86 68 [2] b4 4a [2] b2 7f [2] 9c 7f [2] a3 63 }

  condition:
    any of them
}