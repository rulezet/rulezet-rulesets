rule TTP_XOR_WriteProcessMemory_d06a {
  strings:
    $key_d06a = { 87 18 [2] b5 3a [2] b3 0f [2] 9d 0f [2] a2 13 }

  condition:
    any of them
}