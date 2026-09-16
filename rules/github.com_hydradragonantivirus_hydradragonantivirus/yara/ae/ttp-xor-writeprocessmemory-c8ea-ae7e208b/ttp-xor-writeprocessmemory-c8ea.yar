rule TTP_XOR_WriteProcessMemory_c8ea {
  strings:
    $key_c8ea = { 9f 98 [2] ad ba [2] ab 8f [2] 85 8f [2] ba 93 }

  condition:
    any of them
}