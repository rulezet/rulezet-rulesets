rule TTP_XOR_WriteProcessMemory_cbea {
  strings:
    $key_cbea = { 9c 98 [2] ae ba [2] a8 8f [2] 86 8f [2] b9 93 }

  condition:
    any of them
}