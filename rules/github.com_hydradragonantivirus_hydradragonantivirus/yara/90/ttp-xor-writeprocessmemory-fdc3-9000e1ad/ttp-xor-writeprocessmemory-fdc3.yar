rule TTP_XOR_WriteProcessMemory_fdc3 {
  strings:
    $key_fdc3 = { aa b1 [2] 98 93 [2] 9e a6 [2] b0 a6 [2] 8f ba }

  condition:
    any of them
}