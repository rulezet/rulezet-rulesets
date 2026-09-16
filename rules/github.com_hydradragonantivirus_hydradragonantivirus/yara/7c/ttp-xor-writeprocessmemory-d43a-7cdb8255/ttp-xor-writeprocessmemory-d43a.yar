rule TTP_XOR_WriteProcessMemory_d43a {
  strings:
    $key_d43a = { 83 48 [2] b1 6a [2] b7 5f [2] 99 5f [2] a6 43 }

  condition:
    any of them
}