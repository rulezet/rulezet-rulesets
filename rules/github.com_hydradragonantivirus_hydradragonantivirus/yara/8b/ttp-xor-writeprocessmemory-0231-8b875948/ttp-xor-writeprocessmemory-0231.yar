rule TTP_XOR_WriteProcessMemory_0231 {
  strings:
    $key_0231 = { 55 43 [2] 67 61 [2] 61 54 [2] 4f 54 [2] 70 48 }

  condition:
    any of them
}