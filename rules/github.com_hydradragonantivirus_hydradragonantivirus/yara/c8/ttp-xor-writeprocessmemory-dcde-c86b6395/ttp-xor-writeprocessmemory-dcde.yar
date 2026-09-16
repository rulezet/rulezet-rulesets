rule TTP_XOR_WriteProcessMemory_dcde {
  strings:
    $key_dcde = { 8b ac [2] b9 8e [2] bf bb [2] 91 bb [2] ae a7 }

  condition:
    any of them
}