rule TTP_XOR_WriteProcessMemory_2883 {
  strings:
    $key_2883 = { 7f f1 [2] 4d d3 [2] 4b e6 [2] 65 e6 [2] 5a fa }

  condition:
    any of them
}