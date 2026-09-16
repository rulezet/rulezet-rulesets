rule TTP_XOR_WriteProcessMemory_ebc6 {
  strings:
    $key_ebc6 = { bc b4 [2] 8e 96 [2] 88 a3 [2] a6 a3 [2] 99 bf }

  condition:
    any of them
}