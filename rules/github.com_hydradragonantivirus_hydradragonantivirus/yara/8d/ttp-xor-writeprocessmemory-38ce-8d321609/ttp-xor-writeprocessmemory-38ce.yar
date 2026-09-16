rule TTP_XOR_WriteProcessMemory_38ce {
  strings:
    $key_38ce = { 6f bc [2] 5d 9e [2] 5b ab [2] 75 ab [2] 4a b7 }

  condition:
    any of them
}