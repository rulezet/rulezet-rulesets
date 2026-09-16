rule TTP_XOR_WriteProcessMemory_d53a {
  strings:
    $key_d53a = { 82 48 [2] b0 6a [2] b6 5f [2] 98 5f [2] a7 43 }

  condition:
    any of them
}