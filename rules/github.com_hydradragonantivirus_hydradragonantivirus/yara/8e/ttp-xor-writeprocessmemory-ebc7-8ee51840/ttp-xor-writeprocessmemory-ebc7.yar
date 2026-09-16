rule TTP_XOR_WriteProcessMemory_ebc7 {
  strings:
    $key_ebc7 = { bc b5 [2] 8e 97 [2] 88 a2 [2] a6 a2 [2] 99 be }

  condition:
    any of them
}