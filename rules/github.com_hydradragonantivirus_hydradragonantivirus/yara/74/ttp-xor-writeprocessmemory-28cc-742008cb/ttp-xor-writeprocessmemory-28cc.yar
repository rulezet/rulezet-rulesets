rule TTP_XOR_WriteProcessMemory_28cc {
  strings:
    $key_28cc = { 7f be [2] 4d 9c [2] 4b a9 [2] 65 a9 [2] 5a b5 }

  condition:
    any of them
}