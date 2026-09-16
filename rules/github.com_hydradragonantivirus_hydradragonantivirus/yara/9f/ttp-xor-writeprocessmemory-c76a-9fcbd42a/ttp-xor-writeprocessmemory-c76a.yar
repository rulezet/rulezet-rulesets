rule TTP_XOR_WriteProcessMemory_c76a {
  strings:
    $key_c76a = { 90 18 [2] a2 3a [2] a4 0f [2] 8a 0f [2] b5 13 }

  condition:
    any of them
}