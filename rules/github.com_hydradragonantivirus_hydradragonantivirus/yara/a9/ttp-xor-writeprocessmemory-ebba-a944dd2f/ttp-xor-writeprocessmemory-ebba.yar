rule TTP_XOR_WriteProcessMemory_ebba {
  strings:
    $key_ebba = { bc c8 [2] 8e ea [2] 88 df [2] a6 df [2] 99 c3 }

  condition:
    any of them
}