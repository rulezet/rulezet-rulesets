rule TTP_XOR_WriteProcessMemory_c7fa {
  strings:
    $key_c7fa = { 90 88 [2] a2 aa [2] a4 9f [2] 8a 9f [2] b5 83 }

  condition:
    any of them
}