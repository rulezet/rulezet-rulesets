rule TTP_XOR_WriteProcessMemory_4aa8 {
  strings:
    $key_4aa8 = { 1d da [2] 2f f8 [2] 29 cd [2] 07 cd [2] 38 d1 }

  condition:
    any of them
}