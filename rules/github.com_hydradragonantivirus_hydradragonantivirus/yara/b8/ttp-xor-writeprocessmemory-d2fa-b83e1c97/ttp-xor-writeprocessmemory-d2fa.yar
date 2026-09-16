rule TTP_XOR_WriteProcessMemory_d2fa {
  strings:
    $key_d2fa = { 85 88 [2] b7 aa [2] b1 9f [2] 9f 9f [2] a0 83 }

  condition:
    any of them
}