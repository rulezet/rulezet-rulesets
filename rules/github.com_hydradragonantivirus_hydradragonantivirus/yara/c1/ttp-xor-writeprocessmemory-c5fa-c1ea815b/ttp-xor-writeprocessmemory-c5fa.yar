rule TTP_XOR_WriteProcessMemory_c5fa {
  strings:
    $key_c5fa = { 92 88 [2] a0 aa [2] a6 9f [2] 88 9f [2] b7 83 }

  condition:
    any of them
}