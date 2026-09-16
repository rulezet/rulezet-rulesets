rule TTP_XOR_WriteProcessMemory_c8ed {
  strings:
    $key_c8ed = { 9f 9f [2] ad bd [2] ab 88 [2] 85 88 [2] ba 94 }

  condition:
    any of them
}