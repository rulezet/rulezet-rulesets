rule TTP_XOR_WriteProcessMemory_8962 {
  strings:
    $key_8962 = { de 10 [2] ec 32 [2] ea 07 [2] c4 07 [2] fb 1b }

  condition:
    any of them
}