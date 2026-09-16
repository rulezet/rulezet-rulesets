rule TTP_XOR_WriteProcessMemory_d7fa {
  strings:
    $key_d7fa = { 80 88 [2] b2 aa [2] b4 9f [2] 9a 9f [2] a5 83 }

  condition:
    any of them
}