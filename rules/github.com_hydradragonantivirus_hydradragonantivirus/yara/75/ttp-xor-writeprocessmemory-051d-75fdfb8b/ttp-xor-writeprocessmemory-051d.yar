rule TTP_XOR_WriteProcessMemory_051d {
  strings:
    $key_051d = { 52 6f [2] 60 4d [2] 66 78 [2] 48 78 [2] 77 64 }

  condition:
    any of them
}