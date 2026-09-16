rule TTP_XOR_WriteProcessMemory_4210 {
  strings:
    $key_4210 = { 15 62 [2] 27 40 [2] 21 75 [2] 0f 75 [2] 30 69 }

  condition:
    any of them
}