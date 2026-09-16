rule TTP_XOR_WriteProcessMemory_bec1 {
  strings:
    $key_bec1 = { e9 b3 [2] db 91 [2] dd a4 [2] f3 a4 [2] cc b8 }

  condition:
    any of them
}