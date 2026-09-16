rule TTP_XOR_WriteProcessMemory_62f4 {
  strings:
    $key_62f4 = { 35 86 [2] 07 a4 [2] 01 91 [2] 2f 91 [2] 10 8d }

  condition:
    any of them
}