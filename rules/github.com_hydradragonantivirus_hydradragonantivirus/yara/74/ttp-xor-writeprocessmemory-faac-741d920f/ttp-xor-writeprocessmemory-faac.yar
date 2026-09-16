rule TTP_XOR_WriteProcessMemory_faac {
  strings:
    $key_faac = { ad de [2] 9f fc [2] 99 c9 [2] b7 c9 [2] 88 d5 }

  condition:
    any of them
}