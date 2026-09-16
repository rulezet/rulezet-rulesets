rule TTP_XOR_WriteProcessMemory_fba8 {
  strings:
    $key_fba8 = { ac da [2] 9e f8 [2] 98 cd [2] b6 cd [2] 89 d1 }

  condition:
    any of them
}