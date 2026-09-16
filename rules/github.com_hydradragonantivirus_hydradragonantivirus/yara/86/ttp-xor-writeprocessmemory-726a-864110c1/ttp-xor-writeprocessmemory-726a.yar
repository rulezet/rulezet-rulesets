rule TTP_XOR_WriteProcessMemory_726a {
  strings:
    $key_726a = { 25 18 [2] 17 3a [2] 11 0f [2] 3f 0f [2] 00 13 }

  condition:
    any of them
}