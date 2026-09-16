rule TTP_XOR_WriteProcessMemory_d0ea {
  strings:
    $key_d0ea = { 87 98 [2] b5 ba [2] b3 8f [2] 9d 8f [2] a2 93 }

  condition:
    any of them
}