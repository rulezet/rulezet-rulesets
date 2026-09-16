rule TTP_XOR_WriteProcessMemory_d76a {
  strings:
    $key_d76a = { 80 18 [2] b2 3a [2] b4 0f [2] 9a 0f [2] a5 13 }

  condition:
    any of them
}