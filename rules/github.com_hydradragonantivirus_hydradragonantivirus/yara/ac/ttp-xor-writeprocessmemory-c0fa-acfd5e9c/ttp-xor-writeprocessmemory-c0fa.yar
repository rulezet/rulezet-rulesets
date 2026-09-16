rule TTP_XOR_WriteProcessMemory_c0fa {
  strings:
    $key_c0fa = { 97 88 [2] a5 aa [2] a3 9f [2] 8d 9f [2] b2 83 }

  condition:
    any of them
}