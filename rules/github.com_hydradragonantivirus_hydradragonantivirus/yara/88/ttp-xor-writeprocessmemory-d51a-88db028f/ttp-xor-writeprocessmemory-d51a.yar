rule TTP_XOR_WriteProcessMemory_d51a {
  strings:
    $key_d51a = { 82 68 [2] b0 4a [2] b6 7f [2] 98 7f [2] a7 63 }

  condition:
    any of them
}