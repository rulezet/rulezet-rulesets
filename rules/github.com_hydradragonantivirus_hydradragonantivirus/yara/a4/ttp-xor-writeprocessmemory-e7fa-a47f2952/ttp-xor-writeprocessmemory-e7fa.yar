rule TTP_XOR_WriteProcessMemory_e7fa {
  strings:
    $key_e7fa = { b0 88 [2] 82 aa [2] 84 9f [2] aa 9f [2] 95 83 }

  condition:
    any of them
}