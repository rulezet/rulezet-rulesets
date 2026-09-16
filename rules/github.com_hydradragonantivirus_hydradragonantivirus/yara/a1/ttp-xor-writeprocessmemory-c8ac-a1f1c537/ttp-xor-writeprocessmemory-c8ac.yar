rule TTP_XOR_WriteProcessMemory_c8ac {
  strings:
    $key_c8ac = { 9f de [2] ad fc [2] ab c9 [2] 85 c9 [2] ba d5 }

  condition:
    any of them
}