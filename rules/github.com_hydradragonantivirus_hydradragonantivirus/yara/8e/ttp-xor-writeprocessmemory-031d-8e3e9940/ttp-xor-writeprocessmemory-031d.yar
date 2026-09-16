rule TTP_XOR_WriteProcessMemory_031d {
  strings:
    $key_031d = { 54 6f [2] 66 4d [2] 60 78 [2] 4e 78 [2] 71 64 }

  condition:
    any of them
}