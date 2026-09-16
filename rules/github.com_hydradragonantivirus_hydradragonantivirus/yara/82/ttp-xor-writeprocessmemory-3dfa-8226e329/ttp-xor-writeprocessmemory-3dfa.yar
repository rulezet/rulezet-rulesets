rule TTP_XOR_WriteProcessMemory_3dfa {
  strings:
    $key_3dfa = { 6a 88 [2] 58 aa [2] 5e 9f [2] 70 9f [2] 4f 83 }

  condition:
    any of them
}