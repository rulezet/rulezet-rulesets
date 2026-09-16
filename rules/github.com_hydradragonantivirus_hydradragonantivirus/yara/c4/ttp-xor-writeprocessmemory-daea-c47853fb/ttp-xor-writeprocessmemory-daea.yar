rule TTP_XOR_WriteProcessMemory_daea {
  strings:
    $key_daea = { 8d 98 [2] bf ba [2] b9 8f [2] 97 8f [2] a8 93 }

  condition:
    any of them
}