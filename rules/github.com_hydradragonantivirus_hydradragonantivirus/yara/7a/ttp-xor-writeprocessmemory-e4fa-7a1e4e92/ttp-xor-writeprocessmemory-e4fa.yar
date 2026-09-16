rule TTP_XOR_WriteProcessMemory_e4fa {
  strings:
    $key_e4fa = { b3 88 [2] 81 aa [2] 87 9f [2] a9 9f [2] 96 83 }

  condition:
    any of them
}