rule TTP_XOR_WriteProcessMemory_52ea {
  strings:
    $key_52ea = { 05 98 [2] 37 ba [2] 31 8f [2] 1f 8f [2] 20 93 }

  condition:
    any of them
}