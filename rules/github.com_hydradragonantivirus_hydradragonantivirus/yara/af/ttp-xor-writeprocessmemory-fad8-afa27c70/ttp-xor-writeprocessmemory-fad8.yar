rule TTP_XOR_WriteProcessMemory_fad8 {
  strings:
    $key_fad8 = { ad aa [2] 9f 88 [2] 99 bd [2] b7 bd [2] 88 a1 }

  condition:
    any of them
}