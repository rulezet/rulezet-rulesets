rule TTP_XOR_WriteProcessMemory_285d {
  strings:
    $key_285d = { 7f 2f [2] 4d 0d [2] 4b 38 [2] 65 38 [2] 5a 24 }

  condition:
    any of them
}