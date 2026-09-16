rule TTP_XOR_WriteProcessMemory_c6fa {
  strings:
    $key_c6fa = { 91 88 [2] a3 aa [2] a5 9f [2] 8b 9f [2] b4 83 }

  condition:
    any of them
}