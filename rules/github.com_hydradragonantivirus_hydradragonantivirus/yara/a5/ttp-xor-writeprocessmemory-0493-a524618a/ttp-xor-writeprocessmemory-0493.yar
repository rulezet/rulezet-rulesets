rule TTP_XOR_WriteProcessMemory_0493 {
  strings:
    $key_0493 = { 53 e1 [2] 61 c3 [2] 67 f6 [2] 49 f6 [2] 76 ea }

  condition:
    any of them
}