rule TTP_XOR_WriteProcessMemory_c117 {
  strings:
    $key_c117 = { 96 65 [2] a4 47 [2] a2 72 [2] 8c 72 [2] b3 6e }

  condition:
    any of them
}