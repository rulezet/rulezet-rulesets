rule TTP_XOR_WriteProcessMemory_99ed {
  strings:
    $key_99ed = { ce 9f [2] fc bd [2] fa 88 [2] d4 88 [2] eb 94 }

  condition:
    any of them
}