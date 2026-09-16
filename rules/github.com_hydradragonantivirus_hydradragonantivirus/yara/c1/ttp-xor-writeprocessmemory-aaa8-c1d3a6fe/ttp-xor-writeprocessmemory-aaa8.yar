rule TTP_XOR_WriteProcessMemory_aaa8 {
  strings:
    $key_aaa8 = { fd da [2] cf f8 [2] c9 cd [2] e7 cd [2] d8 d1 }

  condition:
    any of them
}