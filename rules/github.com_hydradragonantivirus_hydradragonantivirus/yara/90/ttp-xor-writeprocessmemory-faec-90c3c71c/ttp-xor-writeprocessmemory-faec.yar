rule TTP_XOR_WriteProcessMemory_faec {
  strings:
    $key_faec = { ad 9e [2] 9f bc [2] 99 89 [2] b7 89 [2] 88 95 }

  condition:
    any of them
}