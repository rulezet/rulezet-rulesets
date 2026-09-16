rule TTP_XOR_WriteProcessMemory_bec4 {
  strings:
    $key_bec4 = { e9 b6 [2] db 94 [2] dd a1 [2] f3 a1 [2] cc bd }

  condition:
    any of them
}