rule TTP_XOR_WriteProcessMemory_c3fa {
  strings:
    $key_c3fa = { 94 88 [2] a6 aa [2] a0 9f [2] 8e 9f [2] b1 83 }

  condition:
    any of them
}