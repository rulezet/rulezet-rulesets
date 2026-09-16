rule TTP_XOR_WriteProcessMemory_fdfa {
  strings:
    $key_fdfa = { aa 88 [2] 98 aa [2] 9e 9f [2] b0 9f [2] 8f 83 }

  condition:
    any of them
}