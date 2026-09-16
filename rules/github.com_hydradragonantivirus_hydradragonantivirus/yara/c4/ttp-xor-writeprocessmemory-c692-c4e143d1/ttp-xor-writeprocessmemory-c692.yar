rule TTP_XOR_WriteProcessMemory_c692 {
  strings:
    $key_c692 = { 91 e0 [2] a3 c2 [2] a5 f7 [2] 8b f7 [2] b4 eb }

  condition:
    any of them
}