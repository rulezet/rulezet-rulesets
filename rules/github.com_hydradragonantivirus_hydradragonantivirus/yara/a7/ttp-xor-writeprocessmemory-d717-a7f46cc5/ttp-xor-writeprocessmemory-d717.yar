rule TTP_XOR_WriteProcessMemory_d717 {
  strings:
    $key_d717 = { 80 65 [2] b2 47 [2] b4 72 [2] 9a 72 [2] a5 6e }

  condition:
    any of them
}